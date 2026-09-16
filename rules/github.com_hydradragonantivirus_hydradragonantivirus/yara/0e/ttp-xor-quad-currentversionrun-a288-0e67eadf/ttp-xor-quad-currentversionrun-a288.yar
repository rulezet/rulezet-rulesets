rule TTP_XOR_QUAD_CurrentVersionRun_a288 {
  strings:
    $key_a288 = { f1 e7 [2] d5 e9 [2] fe c5 [2] d0 e7 [2] c4 fc [2] cb e6 [2] d5 fb [2] d7 fa [2] cc fc [2] d0 fb [2] cc d4 }

  condition:
    any of them
}