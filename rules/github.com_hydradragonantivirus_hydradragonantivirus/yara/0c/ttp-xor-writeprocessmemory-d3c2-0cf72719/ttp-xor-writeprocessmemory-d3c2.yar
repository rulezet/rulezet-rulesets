rule TTP_XOR_WriteProcessMemory_d3c2 {
  strings:
    $key_d3c2 = { 84 b0 [2] b6 92 [2] b0 a7 [2] 9e a7 [2] a1 bb }

  condition:
    any of them
}