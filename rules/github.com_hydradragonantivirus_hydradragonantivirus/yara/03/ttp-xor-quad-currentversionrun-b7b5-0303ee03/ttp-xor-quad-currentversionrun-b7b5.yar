rule TTP_XOR_QUAD_CurrentVersionRun_b7b5 {
  strings:
    $key_b7b5 = { e4 da [2] c0 d4 [2] eb f8 [2] c5 da [2] d1 c1 [2] de db [2] c0 c6 [2] c2 c7 [2] d9 c1 [2] c5 c6 [2] d9 e9 }

  condition:
    any of them
}