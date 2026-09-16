rule TTP_XOR_QUAD_CurrentVersionRun_31d3 {
  strings:
    $key_31d3 = { 62 bc [2] 46 b2 [2] 6d 9e [2] 43 bc [2] 57 a7 [2] 58 bd [2] 46 a0 [2] 44 a1 [2] 5f a7 [2] 43 a0 [2] 5f 8f }

  condition:
    any of them
}