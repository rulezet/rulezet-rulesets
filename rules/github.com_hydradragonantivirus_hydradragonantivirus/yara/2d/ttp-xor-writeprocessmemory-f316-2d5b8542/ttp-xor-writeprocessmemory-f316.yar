rule TTP_XOR_WriteProcessMemory_f316 {
  strings:
    $key_f316 = { a4 64 [2] 96 46 [2] 90 73 [2] be 73 [2] 81 6f }

  condition:
    any of them
}