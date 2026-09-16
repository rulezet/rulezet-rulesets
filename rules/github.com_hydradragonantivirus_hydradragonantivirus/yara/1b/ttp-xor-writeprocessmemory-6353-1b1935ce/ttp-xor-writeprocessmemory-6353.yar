rule TTP_XOR_WriteProcessMemory_6353 {
  strings:
    $key_6353 = { 34 21 [2] 06 03 [2] 00 36 [2] 2e 36 [2] 11 2a }

  condition:
    any of them
}