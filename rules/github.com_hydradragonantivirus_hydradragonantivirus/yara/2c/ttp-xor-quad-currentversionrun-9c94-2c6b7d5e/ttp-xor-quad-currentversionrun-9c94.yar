rule TTP_XOR_QUAD_CurrentVersionRun_9c94 {
  strings:
    $key_9c94 = { cf fb [2] eb f5 [2] c0 d9 [2] ee fb [2] fa e0 [2] f5 fa [2] eb e7 [2] e9 e6 [2] f2 e0 [2] ee e7 [2] f2 c8 }

  condition:
    any of them
}