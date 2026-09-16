rule TTP_XOR_QUAD_CurrentVersionRun_b4c0 {
  strings:
    $key_b4c0 = { e7 af [2] c3 a1 [2] e8 8d [2] c6 af [2] d2 b4 [2] dd ae [2] c3 b3 [2] c1 b2 [2] da b4 [2] c6 b3 [2] da 9c }

  condition:
    any of them
}