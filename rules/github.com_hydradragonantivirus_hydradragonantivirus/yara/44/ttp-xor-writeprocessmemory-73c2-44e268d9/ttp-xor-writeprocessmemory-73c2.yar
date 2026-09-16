rule TTP_XOR_WriteProcessMemory_73c2 {
  strings:
    $key_73c2 = { 24 b0 [2] 16 92 [2] 10 a7 [2] 3e a7 [2] 01 bb }

  condition:
    any of them
}