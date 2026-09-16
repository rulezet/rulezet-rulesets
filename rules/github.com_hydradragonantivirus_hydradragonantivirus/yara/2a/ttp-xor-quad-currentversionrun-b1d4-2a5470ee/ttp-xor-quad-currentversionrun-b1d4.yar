rule TTP_XOR_QUAD_CurrentVersionRun_b1d4 {
  strings:
    $key_b1d4 = { e2 bb [2] c6 b5 [2] ed 99 [2] c3 bb [2] d7 a0 [2] d8 ba [2] c6 a7 [2] c4 a6 [2] df a0 [2] c3 a7 [2] df 88 }

  condition:
    any of them
}