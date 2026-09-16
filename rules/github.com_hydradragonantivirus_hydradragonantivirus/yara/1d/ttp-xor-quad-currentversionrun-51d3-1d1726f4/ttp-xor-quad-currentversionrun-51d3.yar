rule TTP_XOR_QUAD_CurrentVersionRun_51d3 {
  strings:
    $key_51d3 = { 02 bc [2] 26 b2 [2] 0d 9e [2] 23 bc [2] 37 a7 [2] 38 bd [2] 26 a0 [2] 24 a1 [2] 3f a7 [2] 23 a0 [2] 3f 8f }

  condition:
    any of them
}