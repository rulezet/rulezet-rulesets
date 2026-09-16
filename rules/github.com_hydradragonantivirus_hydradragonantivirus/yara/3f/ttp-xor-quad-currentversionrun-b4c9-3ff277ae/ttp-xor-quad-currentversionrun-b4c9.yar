rule TTP_XOR_QUAD_CurrentVersionRun_b4c9 {
  strings:
    $key_b4c9 = { e7 a6 [2] c3 a8 [2] e8 84 [2] c6 a6 [2] d2 bd [2] dd a7 [2] c3 ba [2] c1 bb [2] da bd [2] c6 ba [2] da 95 }

  condition:
    any of them
}