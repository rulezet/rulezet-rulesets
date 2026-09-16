rule TTP_XOR_QUAD_CurrentVersionRun_1ec3 {
  strings:
    $key_1ec3 = { 4d ac [2] 69 a2 [2] 42 8e [2] 6c ac [2] 78 b7 [2] 77 ad [2] 69 b0 [2] 6b b1 [2] 70 b7 [2] 6c b0 [2] 70 9f }

  condition:
    any of them
}