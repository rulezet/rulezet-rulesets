rule TTP_XOR_WriteProcessMemory_15c2 {
  strings:
    $key_15c2 = { 42 b0 [2] 70 92 [2] 76 a7 [2] 58 a7 [2] 67 bb }

  condition:
    any of them
}