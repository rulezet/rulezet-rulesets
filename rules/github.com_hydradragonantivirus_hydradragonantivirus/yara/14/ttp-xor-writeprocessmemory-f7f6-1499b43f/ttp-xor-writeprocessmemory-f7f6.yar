rule TTP_XOR_WriteProcessMemory_f7f6 {
  strings:
    $key_f7f6 = { a0 84 [2] 92 a6 [2] 94 93 [2] ba 93 [2] 85 8f }

  condition:
    any of them
}