rule TTP_XOR_QUAD_CurrentVersionRun_b485 {
  strings:
    $key_b485 = { e7 ea [2] c3 e4 [2] e8 c8 [2] c6 ea [2] d2 f1 [2] dd eb [2] c3 f6 [2] c1 f7 [2] da f1 [2] c6 f6 [2] da d9 }

  condition:
    any of them
}