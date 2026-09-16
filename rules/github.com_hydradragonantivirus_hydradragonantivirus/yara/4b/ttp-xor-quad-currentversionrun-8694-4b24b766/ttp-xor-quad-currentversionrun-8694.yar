rule TTP_XOR_QUAD_CurrentVersionRun_8694 {
  strings:
    $key_8694 = { d5 fb [2] f1 f5 [2] da d9 [2] f4 fb [2] e0 e0 [2] ef fa [2] f1 e7 [2] f3 e6 [2] e8 e0 [2] f4 e7 [2] e8 c8 }

  condition:
    any of them
}