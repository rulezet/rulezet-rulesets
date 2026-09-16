rule TTP_XOR_WriteProcessMemory_7349 {
  strings:
    $key_7349 = { 24 3b [2] 16 19 [2] 10 2c [2] 3e 2c [2] 01 30 }

  condition:
    any of them
}