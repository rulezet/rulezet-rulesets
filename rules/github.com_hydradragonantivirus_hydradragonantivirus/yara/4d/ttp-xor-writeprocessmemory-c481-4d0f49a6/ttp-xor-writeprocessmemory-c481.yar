rule TTP_XOR_WriteProcessMemory_c481 {
  strings:
    $key_c481 = { 93 f3 [2] a1 d1 [2] a7 e4 [2] 89 e4 [2] b6 f8 }

  condition:
    any of them
}