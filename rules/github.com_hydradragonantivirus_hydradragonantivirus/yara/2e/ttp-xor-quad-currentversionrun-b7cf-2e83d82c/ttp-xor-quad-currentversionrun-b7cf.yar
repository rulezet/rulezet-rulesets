rule TTP_XOR_QUAD_CurrentVersionRun_b7cf {
  strings:
    $key_b7cf = { e4 a0 [2] c0 ae [2] eb 82 [2] c5 a0 [2] d1 bb [2] de a1 [2] c0 bc [2] c2 bd [2] d9 bb [2] c5 bc [2] d9 93 }

  condition:
    any of them
}