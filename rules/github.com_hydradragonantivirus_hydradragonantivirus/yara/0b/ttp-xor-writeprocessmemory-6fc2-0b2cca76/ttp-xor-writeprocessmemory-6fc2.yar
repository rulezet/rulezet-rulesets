rule TTP_XOR_WriteProcessMemory_6fc2 {
  strings:
    $key_6fc2 = { 38 b0 [2] 0a 92 [2] 0c a7 [2] 22 a7 [2] 1d bb }

  condition:
    any of them
}