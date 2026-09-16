rule TTP_XOR_WriteProcessMemory_a5c2 {
  strings:
    $key_a5c2 = { f2 b0 [2] c0 92 [2] c6 a7 [2] e8 a7 [2] d7 bb }

  condition:
    any of them
}