rule TTP_XOR_QUAD_CurrentVersionRun_b394 {
  strings:
    $key_b394 = { e0 fb [2] c4 f5 [2] ef d9 [2] c1 fb [2] d5 e0 [2] da fa [2] c4 e7 [2] c6 e6 [2] dd e0 [2] c1 e7 [2] dd c8 }

  condition:
    any of them
}