rule TTP_XOR_QUAD_CurrentVersionRun_a4d3 {
  strings:
    $key_a4d3 = { f7 bc [2] d3 b2 [2] f8 9e [2] d6 bc [2] c2 a7 [2] cd bd [2] d3 a0 [2] d1 a1 [2] ca a7 [2] d6 a0 [2] ca 8f }

  condition:
    any of them
}