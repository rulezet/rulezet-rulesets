rule TTP_XOR_WriteProcessMemory_12c2 {
  strings:
    $key_12c2 = { 45 b0 [2] 77 92 [2] 71 a7 [2] 5f a7 [2] 60 bb }

  condition:
    any of them
}