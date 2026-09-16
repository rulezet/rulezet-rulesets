rule TTP_XOR_WriteProcessMemory_c7c2 {
  strings:
    $key_c7c2 = { 90 b0 [2] a2 92 [2] a4 a7 [2] 8a a7 [2] b5 bb }

  condition:
    any of them
}