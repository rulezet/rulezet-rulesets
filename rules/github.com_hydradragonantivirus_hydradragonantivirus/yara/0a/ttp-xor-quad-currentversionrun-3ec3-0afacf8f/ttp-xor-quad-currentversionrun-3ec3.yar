rule TTP_XOR_QUAD_CurrentVersionRun_3ec3 {
  strings:
    $key_3ec3 = { 6d ac [2] 49 a2 [2] 62 8e [2] 4c ac [2] 58 b7 [2] 57 ad [2] 49 b0 [2] 4b b1 [2] 50 b7 [2] 4c b0 [2] 50 9f }

  condition:
    any of them
}