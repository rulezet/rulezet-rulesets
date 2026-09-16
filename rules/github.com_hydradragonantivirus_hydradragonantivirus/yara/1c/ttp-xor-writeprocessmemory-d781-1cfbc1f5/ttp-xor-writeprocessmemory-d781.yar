rule TTP_XOR_WriteProcessMemory_d781 {
  strings:
    $key_d781 = { 80 f3 [2] b2 d1 [2] b4 e4 [2] 9a e4 [2] a5 f8 }

  condition:
    any of them
}