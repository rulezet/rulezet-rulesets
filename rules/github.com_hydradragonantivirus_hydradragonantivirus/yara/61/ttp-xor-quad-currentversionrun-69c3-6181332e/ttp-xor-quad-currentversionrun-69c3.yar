rule TTP_XOR_QUAD_CurrentVersionRun_69c3 {
  strings:
    $key_69c3 = { 3a ac [2] 1e a2 [2] 35 8e [2] 1b ac [2] 0f b7 [2] 00 ad [2] 1e b0 [2] 1c b1 [2] 07 b7 [2] 1b b0 [2] 07 9f }

  condition:
    any of them
}