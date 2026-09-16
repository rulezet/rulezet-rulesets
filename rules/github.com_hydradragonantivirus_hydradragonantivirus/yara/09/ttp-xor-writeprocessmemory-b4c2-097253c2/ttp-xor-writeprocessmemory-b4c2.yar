rule TTP_XOR_WriteProcessMemory_b4c2 {
  strings:
    $key_b4c2 = { e3 b0 [2] d1 92 [2] d7 a7 [2] f9 a7 [2] c6 bb }

  condition:
    any of them
}