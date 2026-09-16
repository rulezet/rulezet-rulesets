rule TTP_XOR_QUAD_CurrentVersionRun_4dc3 {
  strings:
    $key_4dc3 = { 1e ac [2] 3a a2 [2] 11 8e [2] 3f ac [2] 2b b7 [2] 24 ad [2] 3a b0 [2] 38 b1 [2] 23 b7 [2] 3f b0 [2] 23 9f }

  condition:
    any of them
}