rule TTP_XOR_WriteProcessMemory_6322 {
  strings:
    $key_6322 = { 34 50 [2] 06 72 [2] 00 47 [2] 2e 47 [2] 11 5b }

  condition:
    any of them
}