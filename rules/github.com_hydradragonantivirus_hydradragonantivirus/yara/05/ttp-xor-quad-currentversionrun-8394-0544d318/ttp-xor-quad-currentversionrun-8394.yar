rule TTP_XOR_QUAD_CurrentVersionRun_8394 {
  strings:
    $key_8394 = { d0 fb [2] f4 f5 [2] df d9 [2] f1 fb [2] e5 e0 [2] ea fa [2] f4 e7 [2] f6 e6 [2] ed e0 [2] f1 e7 [2] ed c8 }

  condition:
    any of them
}