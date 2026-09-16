rule TTP_XOR_QUAD_CurrentVersionRun_b3b3 {
  strings:
    $key_b3b3 = { e0 dc [2] c4 d2 [2] ef fe [2] c1 dc [2] d5 c7 [2] da dd [2] c4 c0 [2] c6 c1 [2] dd c7 [2] c1 c0 [2] dd ef }

  condition:
    any of them
}