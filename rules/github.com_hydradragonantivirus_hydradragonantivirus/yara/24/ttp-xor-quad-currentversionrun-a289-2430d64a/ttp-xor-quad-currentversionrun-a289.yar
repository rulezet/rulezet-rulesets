rule TTP_XOR_QUAD_CurrentVersionRun_a289 {
  strings:
    $key_a289 = { f1 e6 [2] d5 e8 [2] fe c4 [2] d0 e6 [2] c4 fd [2] cb e7 [2] d5 fa [2] d7 fb [2] cc fd [2] d0 fa [2] cc d5 }

  condition:
    any of them
}