rule TTP_XOR_QUAD_CurrentVersionRun_bb95 {
  strings:
    $key_bb95 = { e8 fa [2] cc f4 [2] e7 d8 [2] c9 fa [2] dd e1 [2] d2 fb [2] cc e6 [2] ce e7 [2] d5 e1 [2] c9 e6 [2] d5 c9 }

  condition:
    any of them
}