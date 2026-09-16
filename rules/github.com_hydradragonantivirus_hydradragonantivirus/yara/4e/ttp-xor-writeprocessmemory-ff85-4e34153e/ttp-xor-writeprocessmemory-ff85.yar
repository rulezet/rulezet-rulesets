rule TTP_XOR_WriteProcessMemory_ff85 {
  strings:
    $key_ff85 = { a8 f7 [2] 9a d5 [2] 9c e0 [2] b2 e0 [2] 8d fc }

  condition:
    any of them
}