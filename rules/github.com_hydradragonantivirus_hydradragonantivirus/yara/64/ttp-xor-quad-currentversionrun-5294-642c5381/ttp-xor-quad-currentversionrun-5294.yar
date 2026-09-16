rule TTP_XOR_QUAD_CurrentVersionRun_5294 {
  strings:
    $key_5294 = { 01 fb [2] 25 f5 [2] 0e d9 [2] 20 fb [2] 34 e0 [2] 3b fa [2] 25 e7 [2] 27 e6 [2] 3c e0 [2] 20 e7 [2] 3c c8 }

  condition:
    any of them
}