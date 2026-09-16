rule TTP_XOR_WriteProcessMemory_a6c2 {
  strings:
    $key_a6c2 = { f1 b0 [2] c3 92 [2] c5 a7 [2] eb a7 [2] d4 bb }

  condition:
    any of them
}