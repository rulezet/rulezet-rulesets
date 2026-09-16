rule TTP_XOR_WriteProcessMemory_67c2 {
  strings:
    $key_67c2 = { 30 b0 [2] 02 92 [2] 04 a7 [2] 2a a7 [2] 15 bb }

  condition:
    any of them
}