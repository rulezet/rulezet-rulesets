rule TTP_XOR_QUAD_CurrentVersionRun_bb94 {
  strings:
    $key_bb94 = { e8 fb [2] cc f5 [2] e7 d9 [2] c9 fb [2] dd e0 [2] d2 fa [2] cc e7 [2] ce e6 [2] d5 e0 [2] c9 e7 [2] d5 c8 }

  condition:
    any of them
}