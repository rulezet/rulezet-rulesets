rule TTP_XOR_WriteProcessMemory_6343 {
  strings:
    $key_6343 = { 34 31 [2] 06 13 [2] 00 26 [2] 2e 26 [2] 11 3a }

  condition:
    any of them
}