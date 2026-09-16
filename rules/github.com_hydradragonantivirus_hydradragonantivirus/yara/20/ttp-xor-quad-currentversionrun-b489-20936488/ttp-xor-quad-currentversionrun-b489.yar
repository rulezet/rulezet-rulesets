rule TTP_XOR_QUAD_CurrentVersionRun_b489 {
  strings:
    $key_b489 = { e7 e6 [2] c3 e8 [2] e8 c4 [2] c6 e6 [2] d2 fd [2] dd e7 [2] c3 fa [2] c1 fb [2] da fd [2] c6 fa [2] da d5 }

  condition:
    any of them
}