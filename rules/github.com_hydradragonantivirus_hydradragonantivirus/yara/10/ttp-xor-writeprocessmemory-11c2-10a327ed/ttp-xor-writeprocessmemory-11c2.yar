rule TTP_XOR_WriteProcessMemory_11c2 {
  strings:
    $key_11c2 = { 46 b0 [2] 74 92 [2] 72 a7 [2] 5c a7 [2] 63 bb }

  condition:
    any of them
}