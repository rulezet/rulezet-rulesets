rule TTP_XOR_QUAD_CurrentVersionRun_9489 {
  strings:
    $key_9489 = { c7 e6 [2] e3 e8 [2] c8 c4 [2] e6 e6 [2] f2 fd [2] fd e7 [2] e3 fa [2] e1 fb [2] fa fd [2] e6 fa [2] fa d5 }

  condition:
    any of them
}