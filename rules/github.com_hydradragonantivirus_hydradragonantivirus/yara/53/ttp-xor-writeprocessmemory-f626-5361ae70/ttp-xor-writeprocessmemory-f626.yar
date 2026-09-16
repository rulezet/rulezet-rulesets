rule TTP_XOR_WriteProcessMemory_f626 {
  strings:
    $key_f626 = { a1 54 [2] 93 76 [2] 95 43 [2] bb 43 [2] 84 5f }

  condition:
    any of them
}