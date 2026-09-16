rule TTP_XOR_WriteProcessMemory_f5c2 {
  strings:
    $key_f5c2 = { a2 b0 [2] 90 92 [2] 96 a7 [2] b8 a7 [2] 87 bb }

  condition:
    any of them
}