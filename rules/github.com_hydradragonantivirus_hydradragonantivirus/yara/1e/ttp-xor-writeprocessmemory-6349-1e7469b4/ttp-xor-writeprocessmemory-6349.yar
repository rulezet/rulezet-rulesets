rule TTP_XOR_WriteProcessMemory_6349 {
  strings:
    $key_6349 = { 34 3b [2] 06 19 [2] 00 2c [2] 2e 2c [2] 11 30 }

  condition:
    any of them
}