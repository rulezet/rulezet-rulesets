rule TTP_XOR_QUAD_CurrentVersionRun_a595 {
  strings:
    $key_a595 = { f6 fa [2] d2 f4 [2] f9 d8 [2] d7 fa [2] c3 e1 [2] cc fb [2] d2 e6 [2] d0 e7 [2] cb e1 [2] d7 e6 [2] cb c9 }

  condition:
    any of them
}