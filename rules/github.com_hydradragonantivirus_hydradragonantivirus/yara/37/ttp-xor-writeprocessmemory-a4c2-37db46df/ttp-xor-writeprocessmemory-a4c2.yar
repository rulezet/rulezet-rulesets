rule TTP_XOR_WriteProcessMemory_a4c2 {
  strings:
    $key_a4c2 = { f3 b0 [2] c1 92 [2] c7 a7 [2] e9 a7 [2] d6 bb }

  condition:
    any of them
}