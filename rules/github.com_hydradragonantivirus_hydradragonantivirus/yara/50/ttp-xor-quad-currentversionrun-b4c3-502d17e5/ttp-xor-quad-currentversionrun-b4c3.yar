rule TTP_XOR_QUAD_CurrentVersionRun_b4c3 {
  strings:
    $key_b4c3 = { e7 ac [2] c3 a2 [2] e8 8e [2] c6 ac [2] d2 b7 [2] dd ad [2] c3 b0 [2] c1 b1 [2] da b7 [2] c6 b0 [2] da 9f }

  condition:
    any of them
}