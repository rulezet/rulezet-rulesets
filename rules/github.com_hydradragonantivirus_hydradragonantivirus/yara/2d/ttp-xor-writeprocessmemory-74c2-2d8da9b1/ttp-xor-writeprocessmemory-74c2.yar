rule TTP_XOR_WriteProcessMemory_74c2 {
  strings:
    $key_74c2 = { 23 b0 [2] 11 92 [2] 17 a7 [2] 39 a7 [2] 06 bb }

  condition:
    any of them
}