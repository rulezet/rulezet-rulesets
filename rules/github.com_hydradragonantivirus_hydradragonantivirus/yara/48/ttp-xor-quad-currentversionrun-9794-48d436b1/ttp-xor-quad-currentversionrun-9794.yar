rule TTP_XOR_QUAD_CurrentVersionRun_9794 {
  strings:
    $key_9794 = { c4 fb [2] e0 f5 [2] cb d9 [2] e5 fb [2] f1 e0 [2] fe fa [2] e0 e7 [2] e2 e6 [2] f9 e0 [2] e5 e7 [2] f9 c8 }

  condition:
    any of them
}