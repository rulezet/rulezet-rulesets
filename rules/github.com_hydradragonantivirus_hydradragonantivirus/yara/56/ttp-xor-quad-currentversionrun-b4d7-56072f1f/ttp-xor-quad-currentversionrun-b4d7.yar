rule TTP_XOR_QUAD_CurrentVersionRun_b4d7 {
  strings:
    $key_b4d7 = { e7 b8 [2] c3 b6 [2] e8 9a [2] c6 b8 [2] d2 a3 [2] dd b9 [2] c3 a4 [2] c1 a5 [2] da a3 [2] c6 a4 [2] da 8b }

  condition:
    any of them
}