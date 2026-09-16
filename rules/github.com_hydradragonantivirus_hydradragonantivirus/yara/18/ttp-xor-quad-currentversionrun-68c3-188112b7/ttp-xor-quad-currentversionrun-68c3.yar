rule TTP_XOR_QUAD_CurrentVersionRun_68c3 {
  strings:
    $key_68c3 = { 3b ac [2] 1f a2 [2] 34 8e [2] 1a ac [2] 0e b7 [2] 01 ad [2] 1f b0 [2] 1d b1 [2] 06 b7 [2] 1a b0 [2] 06 9f }

  condition:
    any of them
}