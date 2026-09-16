rule TTP_XOR_QUAD_CurrentVersionRun_a594 {
  strings:
    $key_a594 = { f6 fb [2] d2 f5 [2] f9 d9 [2] d7 fb [2] c3 e0 [2] cc fa [2] d2 e7 [2] d0 e6 [2] cb e0 [2] d7 e7 [2] cb c8 }

  condition:
    any of them
}