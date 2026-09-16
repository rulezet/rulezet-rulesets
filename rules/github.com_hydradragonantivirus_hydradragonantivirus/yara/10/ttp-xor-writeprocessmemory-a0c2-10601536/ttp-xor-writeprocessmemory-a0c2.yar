rule TTP_XOR_WriteProcessMemory_a0c2 {
  strings:
    $key_a0c2 = { f7 b0 [2] c5 92 [2] c3 a7 [2] ed a7 [2] d2 bb }

  condition:
    any of them
}