rule TTP_XOR_WriteProcessMemory_ff82 {
  strings:
    $key_ff82 = { a8 f0 [2] 9a d2 [2] 9c e7 [2] b2 e7 [2] 8d fb }

  condition:
    any of them
}