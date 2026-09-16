rule TTP_XOR_QUAD_CurrentVersionRun_b3d4 {
  strings:
    $key_b3d4 = { e0 bb [2] c4 b5 [2] ef 99 [2] c1 bb [2] d5 a0 [2] da ba [2] c4 a7 [2] c6 a6 [2] dd a0 [2] c1 a7 [2] dd 88 }

  condition:
    any of them
}