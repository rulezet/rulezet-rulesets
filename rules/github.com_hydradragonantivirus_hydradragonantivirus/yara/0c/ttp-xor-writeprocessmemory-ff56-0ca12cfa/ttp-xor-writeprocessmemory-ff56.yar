rule TTP_XOR_WriteProcessMemory_ff56 {
  strings:
    $key_ff56 = { a8 24 [2] 9a 06 [2] 9c 33 [2] b2 33 [2] 8d 2f }

  condition:
    any of them
}