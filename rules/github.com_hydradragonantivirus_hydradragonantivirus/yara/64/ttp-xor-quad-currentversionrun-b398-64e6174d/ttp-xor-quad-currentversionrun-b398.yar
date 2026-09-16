rule TTP_XOR_QUAD_CurrentVersionRun_b398 {
  strings:
    $key_b398 = { e0 f7 [2] c4 f9 [2] ef d5 [2] c1 f7 [2] d5 ec [2] da f6 [2] c4 eb [2] c6 ea [2] dd ec [2] c1 eb [2] dd c4 }

  condition:
    any of them
}