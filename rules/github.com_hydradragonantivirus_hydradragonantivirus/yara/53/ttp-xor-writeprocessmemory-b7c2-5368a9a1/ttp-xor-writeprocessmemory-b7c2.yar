rule TTP_XOR_WriteProcessMemory_b7c2 {
  strings:
    $key_b7c2 = { e0 b0 [2] d2 92 [2] d4 a7 [2] fa a7 [2] c5 bb }

  condition:
    any of them
}