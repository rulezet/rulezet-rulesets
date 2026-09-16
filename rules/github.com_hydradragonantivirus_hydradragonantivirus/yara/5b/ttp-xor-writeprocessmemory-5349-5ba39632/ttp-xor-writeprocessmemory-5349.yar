rule TTP_XOR_WriteProcessMemory_5349 {
  strings:
    $key_5349 = { 04 3b [2] 36 19 [2] 30 2c [2] 1e 2c [2] 21 30 }

  condition:
    any of them
}