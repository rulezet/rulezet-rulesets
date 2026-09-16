rule TTP_XOR_WriteProcessMemory_a7c2 {
  strings:
    $key_a7c2 = { f0 b0 [2] c2 92 [2] c4 a7 [2] ea a7 [2] d5 bb }

  condition:
    any of them
}