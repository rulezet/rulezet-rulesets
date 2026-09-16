rule TTP_XOR_WriteProcessMemory_6356 {
  strings:
    $key_6356 = { 34 24 [2] 06 06 [2] 00 33 [2] 2e 33 [2] 11 2f }

  condition:
    any of them
}