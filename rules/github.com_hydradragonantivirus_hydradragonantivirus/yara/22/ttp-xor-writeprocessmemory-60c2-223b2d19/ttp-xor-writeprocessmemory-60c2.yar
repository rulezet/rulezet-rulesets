rule TTP_XOR_WriteProcessMemory_60c2 {
  strings:
    $key_60c2 = { 37 b0 [2] 05 92 [2] 03 a7 [2] 2d a7 [2] 12 bb }

  condition:
    any of them
}