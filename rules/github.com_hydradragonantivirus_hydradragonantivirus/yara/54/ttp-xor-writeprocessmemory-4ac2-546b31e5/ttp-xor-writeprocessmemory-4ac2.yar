rule TTP_XOR_WriteProcessMemory_4ac2 {
  strings:
    $key_4ac2 = { 1d b0 [2] 2f 92 [2] 29 a7 [2] 07 a7 [2] 38 bb }

  condition:
    any of them
}