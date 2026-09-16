rule TTP_XOR_QUAD_CurrentVersionRun_9894 {
  strings:
    $key_9894 = { cb fb [2] ef f5 [2] c4 d9 [2] ea fb [2] fe e0 [2] f1 fa [2] ef e7 [2] ed e6 [2] f6 e0 [2] ea e7 [2] f6 c8 }

  condition:
    any of them
}