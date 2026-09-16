rule TTP_XOR_QUAD_CurrentVersionRun_5ec3 {
  strings:
    $key_5ec3 = { 0d ac [2] 29 a2 [2] 02 8e [2] 2c ac [2] 38 b7 [2] 37 ad [2] 29 b0 [2] 2b b1 [2] 30 b7 [2] 2c b0 [2] 30 9f }

  condition:
    any of them
}