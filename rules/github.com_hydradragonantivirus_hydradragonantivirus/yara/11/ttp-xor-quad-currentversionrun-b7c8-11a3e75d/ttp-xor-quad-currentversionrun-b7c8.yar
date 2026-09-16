rule TTP_XOR_QUAD_CurrentVersionRun_b7c8 {
  strings:
    $key_b7c8 = { e4 a7 [2] c0 a9 [2] eb 85 [2] c5 a7 [2] d1 bc [2] de a6 [2] c0 bb [2] c2 ba [2] d9 bc [2] c5 bb [2] d9 94 }

  condition:
    any of them
}