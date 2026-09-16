rule TTP_XOR_QUAD_CurrentVersionRun_b4c8 {
  strings:
    $key_b4c8 = { e7 a7 [2] c3 a9 [2] e8 85 [2] c6 a7 [2] d2 bc [2] dd a6 [2] c3 bb [2] c1 ba [2] da bc [2] c6 bb [2] da 94 }

  condition:
    any of them
}