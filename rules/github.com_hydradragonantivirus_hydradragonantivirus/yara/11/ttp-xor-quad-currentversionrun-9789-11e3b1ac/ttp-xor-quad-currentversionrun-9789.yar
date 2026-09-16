rule TTP_XOR_QUAD_CurrentVersionRun_9789 {
  strings:
    $key_9789 = { c4 e6 [2] e0 e8 [2] cb c4 [2] e5 e6 [2] f1 fd [2] fe e7 [2] e0 fa [2] e2 fb [2] f9 fd [2] e5 fa [2] f9 d5 }

  condition:
    any of them
}