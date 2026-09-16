rule TTP_XOR_WriteProcessMemory_ca81 {
  strings:
    $key_ca81 = { 9d f3 [2] af d1 [2] a9 e4 [2] 87 e4 [2] b8 f8 }

  condition:
    any of them
}