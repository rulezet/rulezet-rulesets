rule TTP_XOR_WriteProcessMemory_21c2 {
  strings:
    $key_21c2 = { 76 b0 [2] 44 92 [2] 42 a7 [2] 6c a7 [2] 53 bb }

  condition:
    any of them
}