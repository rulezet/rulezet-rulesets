rule TTP_XOR_QUAD_CurrentVersionRun_a3d3 {
  strings:
    $key_a3d3 = { f0 bc [2] d4 b2 [2] ff 9e [2] d1 bc [2] c5 a7 [2] ca bd [2] d4 a0 [2] d6 a1 [2] cd a7 [2] d1 a0 [2] cd 8f }

  condition:
    any of them
}