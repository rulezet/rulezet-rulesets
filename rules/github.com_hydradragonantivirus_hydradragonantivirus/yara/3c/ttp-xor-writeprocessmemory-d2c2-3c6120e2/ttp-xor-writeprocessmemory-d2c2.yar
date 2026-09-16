rule TTP_XOR_WriteProcessMemory_d2c2 {
  strings:
    $key_d2c2 = { 85 b0 [2] b7 92 [2] b1 a7 [2] 9f a7 [2] a0 bb }

  condition:
    any of them
}