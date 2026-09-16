rule TTP_XOR_QUAD_CurrentVersionRun_b3d7 {
  strings:
    $key_b3d7 = { e0 b8 [2] c4 b6 [2] ef 9a [2] c1 b8 [2] d5 a3 [2] da b9 [2] c4 a4 [2] c6 a5 [2] dd a3 [2] c1 a4 [2] dd 8b }

  condition:
    any of them
}