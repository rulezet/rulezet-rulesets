rule TTP_XOR_WriteProcessMemory_d7b1 {
  strings:
    $key_d7b1 = { 80 c3 [2] b2 e1 [2] b4 d4 [2] 9a d4 [2] a5 c8 }

  condition:
    any of them
}