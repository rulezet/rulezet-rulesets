rule TTP_XOR_WriteProcessMemory_f0c2 {
  strings:
    $key_f0c2 = { a7 b0 [2] 95 92 [2] 93 a7 [2] bd a7 [2] 82 bb }

  condition:
    any of them
}