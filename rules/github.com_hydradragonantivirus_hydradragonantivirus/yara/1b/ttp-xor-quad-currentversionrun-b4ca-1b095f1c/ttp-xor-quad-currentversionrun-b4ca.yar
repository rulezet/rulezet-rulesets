rule TTP_XOR_QUAD_CurrentVersionRun_b4ca {
  strings:
    $key_b4ca = { e7 a5 [2] c3 ab [2] e8 87 [2] c6 a5 [2] d2 be [2] dd a4 [2] c3 b9 [2] c1 b8 [2] da be [2] c6 b9 [2] da 96 }

  condition:
    any of them
}