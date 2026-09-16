rule TTP_XOR_QUAD_CurrentVersionRun_b1c9 {
  strings:
    $key_b1c9 = { e2 a6 [2] c6 a8 [2] ed 84 [2] c3 a6 [2] d7 bd [2] d8 a7 [2] c6 ba [2] c4 bb [2] df bd [2] c3 ba [2] df 95 }

  condition:
    any of them
}