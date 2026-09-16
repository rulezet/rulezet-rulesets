rule TTP_XOR_QUAD_CurrentVersionRun_b384 {
  strings:
    $key_b384 = { e0 eb [2] c4 e5 [2] ef c9 [2] c1 eb [2] d5 f0 [2] da ea [2] c4 f7 [2] c6 f6 [2] dd f0 [2] c1 f7 [2] dd d8 }

  condition:
    any of them
}