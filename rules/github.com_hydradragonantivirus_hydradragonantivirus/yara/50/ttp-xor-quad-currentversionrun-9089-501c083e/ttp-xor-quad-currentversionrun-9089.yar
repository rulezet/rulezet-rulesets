rule TTP_XOR_QUAD_CurrentVersionRun_9089 {
  strings:
    $key_9089 = { c3 e6 [2] e7 e8 [2] cc c4 [2] e2 e6 [2] f6 fd [2] f9 e7 [2] e7 fa [2] e5 fb [2] fe fd [2] e2 fa [2] fe d5 }

  condition:
    any of them
}