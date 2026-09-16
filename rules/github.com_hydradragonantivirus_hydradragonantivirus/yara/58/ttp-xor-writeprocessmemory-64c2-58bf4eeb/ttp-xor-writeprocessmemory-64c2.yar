rule TTP_XOR_WriteProcessMemory_64c2 {
  strings:
    $key_64c2 = { 33 b0 [2] 01 92 [2] 07 a7 [2] 29 a7 [2] 16 bb }

  condition:
    any of them
}