rule TTP_XOR_QUAD_CurrentVersionRun_be95 {
  strings:
    $key_be95 = { ed fa [2] c9 f4 [2] e2 d8 [2] cc fa [2] d8 e1 [2] d7 fb [2] c9 e6 [2] cb e7 [2] d0 e1 [2] cc e6 [2] d0 c9 }

  condition:
    any of them
}