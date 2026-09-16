rule TTP_XOR_WriteProcessMemory_c781 {
  strings:
    $key_c781 = { 90 f3 [2] a2 d1 [2] a4 e4 [2] 8a e4 [2] b5 f8 }

  condition:
    any of them
}