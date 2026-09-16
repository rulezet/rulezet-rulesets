rule TTP_XOR_WriteProcessMemory_ca80 {
  strings:
    $key_ca80 = { 9d f2 [2] af d0 [2] a9 e5 [2] 87 e5 [2] b8 f9 }

  condition:
    any of them
}