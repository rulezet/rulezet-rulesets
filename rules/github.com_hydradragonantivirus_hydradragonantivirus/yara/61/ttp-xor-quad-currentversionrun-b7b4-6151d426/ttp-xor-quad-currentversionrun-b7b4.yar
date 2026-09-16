rule TTP_XOR_QUAD_CurrentVersionRun_b7b4 {
  strings:
    $key_b7b4 = { e4 db [2] c0 d5 [2] eb f9 [2] c5 db [2] d1 c0 [2] de da [2] c0 c7 [2] c2 c6 [2] d9 c0 [2] c5 c7 [2] d9 e8 }

  condition:
    any of them
}