rule TTP_XOR_WriteProcessMemory_5142 {
  strings:
    $key_5142 = { 06 30 [2] 34 12 [2] 32 27 [2] 1c 27 [2] 23 3b }

  condition:
    any of them
}