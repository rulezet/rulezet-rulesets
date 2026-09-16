rule TTP_XOR_WriteProcessMemory_78a2 {
  strings:
    $key_78a2 = { 2f d0 [2] 1d f2 [2] 1b c7 [2] 35 c7 [2] 0a db }

  condition:
    any of them
}