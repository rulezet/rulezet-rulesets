rule TTP_XOR_QUAD_CurrentVersionRun_b4cf {
  strings:
    $key_b4cf = { e7 a0 [2] c3 ae [2] e8 82 [2] c6 a0 [2] d2 bb [2] dd a1 [2] c3 bc [2] c1 bd [2] da bb [2] c6 bc [2] da 93 }

  condition:
    any of them
}