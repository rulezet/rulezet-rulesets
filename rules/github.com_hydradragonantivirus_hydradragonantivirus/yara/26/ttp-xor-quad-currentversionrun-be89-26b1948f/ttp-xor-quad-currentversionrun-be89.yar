rule TTP_XOR_QUAD_CurrentVersionRun_be89 {
  strings:
    $key_be89 = { ed e6 [2] c9 e8 [2] e2 c4 [2] cc e6 [2] d8 fd [2] d7 e7 [2] c9 fa [2] cb fb [2] d0 fd [2] cc fa [2] d0 d5 }

  condition:
    any of them
}