rule TTP_XOR_QUAD_CurrentVersionRun_a295 {
  strings:
    $key_a295 = { f1 fa [2] d5 f4 [2] fe d8 [2] d0 fa [2] c4 e1 [2] cb fb [2] d5 e6 [2] d7 e7 [2] cc e1 [2] d0 e6 [2] cc c9 }

  condition:
    any of them
}