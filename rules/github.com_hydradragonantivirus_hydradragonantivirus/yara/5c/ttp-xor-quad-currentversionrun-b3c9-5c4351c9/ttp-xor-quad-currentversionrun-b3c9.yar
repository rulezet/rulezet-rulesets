rule TTP_XOR_QUAD_CurrentVersionRun_b3c9 {
  strings:
    $key_b3c9 = { e0 a6 [2] c4 a8 [2] ef 84 [2] c1 a6 [2] d5 bd [2] da a7 [2] c4 ba [2] c6 bb [2] dd bd [2] c1 ba [2] dd 95 }

  condition:
    any of them
}