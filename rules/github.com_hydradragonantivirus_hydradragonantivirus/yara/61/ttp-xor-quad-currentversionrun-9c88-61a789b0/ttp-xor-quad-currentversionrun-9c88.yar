rule TTP_XOR_QUAD_CurrentVersionRun_9c88 {
  strings:
    $key_9c88 = { cf e7 [2] eb e9 [2] c0 c5 [2] ee e7 [2] fa fc [2] f5 e6 [2] eb fb [2] e9 fa [2] f2 fc [2] ee fb [2] f2 d4 }

  condition:
    any of them
}