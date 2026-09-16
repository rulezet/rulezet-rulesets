rule TTP_XOR_WriteProcessMemory_f746 {
  strings:
    $key_f746 = { a0 34 [2] 92 16 [2] 94 23 [2] ba 23 [2] 85 3f }

  condition:
    any of them
}