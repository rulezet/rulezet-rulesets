rule TTP_XOR_WriteProcessMemory_f646 {
  strings:
    $key_f646 = { a1 34 [2] 93 16 [2] 95 23 [2] bb 23 [2] 84 3f }

  condition:
    any of them
}