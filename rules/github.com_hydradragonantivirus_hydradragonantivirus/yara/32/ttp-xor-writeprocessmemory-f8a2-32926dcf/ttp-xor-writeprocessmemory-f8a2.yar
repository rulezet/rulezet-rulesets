rule TTP_XOR_WriteProcessMemory_f8a2 {
  strings:
    $key_f8a2 = { af d0 [2] 9d f2 [2] 9b c7 [2] b5 c7 [2] 8a db }

  condition:
    any of them
}