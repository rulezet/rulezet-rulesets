rule TTP_XOR_QUAD_CurrentVersionRun_a7d3 {
  strings:
    $key_a7d3 = { f4 bc [2] d0 b2 [2] fb 9e [2] d5 bc [2] c1 a7 [2] ce bd [2] d0 a0 [2] d2 a1 [2] c9 a7 [2] d5 a0 [2] c9 8f }

  condition:
    any of them
}