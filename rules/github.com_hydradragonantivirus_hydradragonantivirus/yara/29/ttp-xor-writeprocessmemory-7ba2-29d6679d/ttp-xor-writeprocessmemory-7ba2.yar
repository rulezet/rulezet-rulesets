rule TTP_XOR_WriteProcessMemory_7ba2 {
  strings:
    $key_7ba2 = { 2c d0 [2] 1e f2 [2] 18 c7 [2] 36 c7 [2] 09 db }

  condition:
    any of them
}