rule TTP_XOR_WriteProcessMemory_f616 {
  strings:
    $key_f616 = { a1 64 [2] 93 46 [2] 95 73 [2] bb 73 [2] 84 6f }

  condition:
    any of them
}