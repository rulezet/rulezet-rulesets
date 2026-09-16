rule TTP_XOR_WriteProcessMemory_fff6 {
  strings:
    $key_fff6 = { a8 84 [2] 9a a6 [2] 9c 93 [2] b2 93 [2] 8d 8f }

  condition:
    any of them
}