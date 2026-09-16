rule TTP_XOR_QUAD_CurrentVersionRun_41d3 {
  strings:
    $key_41d3 = { 12 bc [2] 36 b2 [2] 1d 9e [2] 33 bc [2] 27 a7 [2] 28 bd [2] 36 a0 [2] 34 a1 [2] 2f a7 [2] 33 a0 [2] 2f 8f }

  condition:
    any of them
}