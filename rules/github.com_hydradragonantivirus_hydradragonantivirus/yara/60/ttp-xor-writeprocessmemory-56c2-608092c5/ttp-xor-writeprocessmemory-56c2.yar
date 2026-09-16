rule TTP_XOR_WriteProcessMemory_56c2 {
  strings:
    $key_56c2 = { 01 b0 [2] 33 92 [2] 35 a7 [2] 1b a7 [2] 24 bb }

  condition:
    any of them
}