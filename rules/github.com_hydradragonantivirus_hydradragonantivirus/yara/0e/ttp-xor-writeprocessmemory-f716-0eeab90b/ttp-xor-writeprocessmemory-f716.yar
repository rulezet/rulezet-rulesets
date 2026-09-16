rule TTP_XOR_WriteProcessMemory_f716 {
  strings:
    $key_f716 = { a0 64 [2] 92 46 [2] 94 73 [2] ba 73 [2] 85 6f }

  condition:
    any of them
}