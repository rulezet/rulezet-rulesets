rule TTP_XOR_QUAD_CurrentVersionRun_b39b {
  strings:
    $key_b39b = { e0 f4 [2] c4 fa [2] ef d6 [2] c1 f4 [2] d5 ef [2] da f5 [2] c4 e8 [2] c6 e9 [2] dd ef [2] c1 e8 [2] dd c7 }

  condition:
    any of them
}