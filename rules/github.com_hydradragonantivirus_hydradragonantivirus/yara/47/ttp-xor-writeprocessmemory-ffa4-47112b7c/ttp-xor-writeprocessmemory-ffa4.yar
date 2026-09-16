rule TTP_XOR_WriteProcessMemory_ffa4 {
  strings:
    $key_ffa4 = { a8 d6 [2] 9a f4 [2] 9c c1 [2] b2 c1 [2] 8d dd }

  condition:
    any of them
}