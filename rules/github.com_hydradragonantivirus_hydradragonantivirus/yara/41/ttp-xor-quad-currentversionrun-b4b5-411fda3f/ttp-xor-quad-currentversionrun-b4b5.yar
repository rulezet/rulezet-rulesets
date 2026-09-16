rule TTP_XOR_QUAD_CurrentVersionRun_b4b5 {
  strings:
    $key_b4b5 = { e7 da [2] c3 d4 [2] e8 f8 [2] c6 da [2] d2 c1 [2] dd db [2] c3 c6 [2] c1 c7 [2] da c1 [2] c6 c6 [2] da e9 }

  condition:
    any of them
}