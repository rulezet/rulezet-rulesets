rule TTP_XOR_WriteProcessMemory_41c2 {
  strings:
    $key_41c2 = { 16 b0 [2] 24 92 [2] 22 a7 [2] 0c a7 [2] 33 bb }

  condition:
    any of them
}