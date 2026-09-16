rule TTP_XOR_WriteProcessMemory_63c2 {
  strings:
    $key_63c2 = { 34 b0 [2] 06 92 [2] 00 a7 [2] 2e a7 [2] 11 bb }

  condition:
    any of them
}