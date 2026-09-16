rule TTP_XOR_WriteProcessMemory_75c2 {
  strings:
    $key_75c2 = { 22 b0 [2] 10 92 [2] 16 a7 [2] 38 a7 [2] 07 bb }

  condition:
    any of them
}