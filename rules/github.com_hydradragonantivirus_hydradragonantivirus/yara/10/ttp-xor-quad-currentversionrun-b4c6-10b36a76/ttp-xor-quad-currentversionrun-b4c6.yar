rule TTP_XOR_QUAD_CurrentVersionRun_b4c6 {
  strings:
    $key_b4c6 = { e7 a9 [2] c3 a7 [2] e8 8b [2] c6 a9 [2] d2 b2 [2] dd a8 [2] c3 b5 [2] c1 b4 [2] da b2 [2] c6 b5 [2] da 9a }

  condition:
    any of them
}