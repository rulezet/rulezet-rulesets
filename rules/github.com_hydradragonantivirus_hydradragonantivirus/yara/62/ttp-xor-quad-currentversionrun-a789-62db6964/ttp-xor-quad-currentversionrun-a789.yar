rule TTP_XOR_QUAD_CurrentVersionRun_a789 {
  strings:
    $key_a789 = { f4 e6 [2] d0 e8 [2] fb c4 [2] d5 e6 [2] c1 fd [2] ce e7 [2] d0 fa [2] d2 fb [2] c9 fd [2] d5 fa [2] c9 d5 }

  condition:
    any of them
}