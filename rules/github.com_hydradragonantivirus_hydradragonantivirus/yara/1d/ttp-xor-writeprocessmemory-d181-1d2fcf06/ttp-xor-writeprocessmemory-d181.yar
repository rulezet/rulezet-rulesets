rule TTP_XOR_WriteProcessMemory_d181 {
  strings:
    $key_d181 = { 86 f3 [2] b4 d1 [2] b2 e4 [2] 9c e4 [2] a3 f8 }

  condition:
    any of them
}