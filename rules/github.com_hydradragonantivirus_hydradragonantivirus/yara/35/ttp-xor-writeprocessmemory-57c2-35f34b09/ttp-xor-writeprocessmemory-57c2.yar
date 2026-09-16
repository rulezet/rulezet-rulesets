rule TTP_XOR_WriteProcessMemory_57c2 {
  strings:
    $key_57c2 = { 00 b0 [2] 32 92 [2] 34 a7 [2] 1a a7 [2] 25 bb }

  condition:
    any of them
}