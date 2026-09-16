rule TTP_XOR_WriteProcessMemory_3349 {
  strings:
    $key_3349 = { 64 3b [2] 56 19 [2] 50 2c [2] 7e 2c [2] 41 30 }

  condition:
    any of them
}