rule TTP_XOR_WriteProcessMemory_7142 {
  strings:
    $key_7142 = { 26 30 [2] 14 12 [2] 12 27 [2] 3c 27 [2] 03 3b }

  condition:
    any of them
}