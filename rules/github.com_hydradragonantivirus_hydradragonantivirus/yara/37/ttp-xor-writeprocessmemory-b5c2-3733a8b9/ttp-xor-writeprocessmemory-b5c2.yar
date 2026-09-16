rule TTP_XOR_WriteProcessMemory_b5c2 {
  strings:
    $key_b5c2 = { e2 b0 [2] d0 92 [2] d6 a7 [2] f8 a7 [2] c7 bb }

  condition:
    any of them
}