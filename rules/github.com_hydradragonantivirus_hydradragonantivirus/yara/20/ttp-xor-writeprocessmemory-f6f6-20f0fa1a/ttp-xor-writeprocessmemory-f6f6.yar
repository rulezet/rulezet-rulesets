rule TTP_XOR_WriteProcessMemory_f6f6 {
  strings:
    $key_f6f6 = { a1 84 [2] 93 a6 [2] 95 93 [2] bb 93 [2] 84 8f }

  condition:
    any of them
}