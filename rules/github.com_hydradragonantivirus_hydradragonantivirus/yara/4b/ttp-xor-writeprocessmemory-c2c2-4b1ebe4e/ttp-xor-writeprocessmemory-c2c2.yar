rule TTP_XOR_WriteProcessMemory_c2c2 {
  strings:
    $key_c2c2 = { 95 b0 [2] a7 92 [2] a1 a7 [2] 8f a7 [2] b0 bb }

  condition:
    any of them
}