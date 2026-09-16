rule TTP_XOR_QUAD_CurrentVersionRun_b194 {
  strings:
    $key_b194 = { e2 fb [2] c6 f5 [2] ed d9 [2] c3 fb [2] d7 e0 [2] d8 fa [2] c6 e7 [2] c4 e6 [2] df e0 [2] c3 e7 [2] df c8 }

  condition:
    any of them
}