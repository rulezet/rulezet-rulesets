rule TTP_XOR_WriteProcessMemory_f7e6 {
  strings:
    $key_f7e6 = { a0 94 [2] 92 b6 [2] 94 83 [2] ba 83 [2] 85 9f }

  condition:
    any of them
}