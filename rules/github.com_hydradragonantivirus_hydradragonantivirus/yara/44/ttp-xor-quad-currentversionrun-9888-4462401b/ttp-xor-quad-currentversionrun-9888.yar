rule TTP_XOR_QUAD_CurrentVersionRun_9888 {
  strings:
    $key_9888 = { cb e7 [2] ef e9 [2] c4 c5 [2] ea e7 [2] fe fc [2] f1 e6 [2] ef fb [2] ed fa [2] f6 fc [2] ea fb [2] f6 d4 }

  condition:
    any of them
}