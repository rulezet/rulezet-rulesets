rule TTP_XOR_WriteProcessMemory_6542 {
  strings:
    $key_6542 = { 32 30 [2] 00 12 [2] 06 27 [2] 28 27 [2] 17 3b }

  condition:
    any of them
}