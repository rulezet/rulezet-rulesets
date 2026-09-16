rule TTP_XOR_QUAD_CurrentVersionRun_b4d6 {
  strings:
    $key_b4d6 = { e7 b9 [2] c3 b7 [2] e8 9b [2] c6 b9 [2] d2 a2 [2] dd b8 [2] c3 a5 [2] c1 a4 [2] da a2 [2] c6 a5 [2] da 8a }

  condition:
    any of them
}