rule TTP_XOR_QUAD_CurrentVersionRun_a589 {
  strings:
    $key_a589 = { f6 e6 [2] d2 e8 [2] f9 c4 [2] d7 e6 [2] c3 fd [2] cc e7 [2] d2 fa [2] d0 fb [2] cb fd [2] d7 fa [2] cb d5 }

  condition:
    any of them
}