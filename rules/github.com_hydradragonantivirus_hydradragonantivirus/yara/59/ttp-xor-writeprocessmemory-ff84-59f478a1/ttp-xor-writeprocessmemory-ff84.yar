rule TTP_XOR_WriteProcessMemory_ff84 {
  strings:
    $key_ff84 = { a8 f6 [2] 9a d4 [2] 9c e1 [2] b2 e1 [2] 8d fd }

  condition:
    any of them
}