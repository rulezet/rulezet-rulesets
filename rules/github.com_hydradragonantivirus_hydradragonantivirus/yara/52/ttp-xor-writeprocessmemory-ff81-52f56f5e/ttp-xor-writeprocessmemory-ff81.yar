rule TTP_XOR_WriteProcessMemory_ff81 {
  strings:
    $key_ff81 = { a8 f3 [2] 9a d1 [2] 9c e4 [2] b2 e4 [2] 8d f8 }

  condition:
    any of them
}