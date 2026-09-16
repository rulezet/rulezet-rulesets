rule TTP_XOR_WriteProcessMemory_10c2 {
  strings:
    $key_10c2 = { 47 b0 [2] 75 92 [2] 73 a7 [2] 5d a7 [2] 62 bb }

  condition:
    any of them
}