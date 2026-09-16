rule TTP_XOR_WriteProcessMemory_ff16 {
  strings:
    $key_ff16 = { a8 64 [2] 9a 46 [2] 9c 73 [2] b2 73 [2] 8d 6f }

  condition:
    any of them
}