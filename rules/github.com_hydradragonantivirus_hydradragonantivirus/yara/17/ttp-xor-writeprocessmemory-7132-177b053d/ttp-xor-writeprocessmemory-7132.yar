rule TTP_XOR_WriteProcessMemory_7132 {
  strings:
    $key_7132 = { 26 40 [2] 14 62 [2] 12 57 [2] 3c 57 [2] 03 4b }

  condition:
    any of them
}