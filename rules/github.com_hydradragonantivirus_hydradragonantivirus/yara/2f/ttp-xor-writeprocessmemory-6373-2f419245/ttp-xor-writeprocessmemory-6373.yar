rule TTP_XOR_WriteProcessMemory_6373 {
  strings:
    $key_6373 = { 34 01 [2] 06 23 [2] 00 16 [2] 2e 16 [2] 11 0a }

  condition:
    any of them
}