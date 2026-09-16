rule TTP_XOR_WriteProcessMemory_4d49 {
  strings:
    $key_4d49 = { 1a 3b [2] 28 19 [2] 2e 2c [2] 00 2c [2] 3f 30 }

  condition:
    any of them
}