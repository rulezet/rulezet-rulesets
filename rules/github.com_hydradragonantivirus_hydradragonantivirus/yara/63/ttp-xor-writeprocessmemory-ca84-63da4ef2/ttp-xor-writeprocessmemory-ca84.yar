rule TTP_XOR_WriteProcessMemory_ca84 {
  strings:
    $key_ca84 = { 9d f6 [2] af d4 [2] a9 e1 [2] 87 e1 [2] b8 fd }

  condition:
    any of them
}