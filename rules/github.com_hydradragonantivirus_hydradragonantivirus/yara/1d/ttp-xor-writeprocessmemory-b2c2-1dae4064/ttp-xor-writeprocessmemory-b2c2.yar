rule TTP_XOR_WriteProcessMemory_b2c2 {
  strings:
    $key_b2c2 = { e5 b0 [2] d7 92 [2] d1 a7 [2] ff a7 [2] c0 bb }

  condition:
    any of them
}