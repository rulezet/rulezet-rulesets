rule TTP_XOR_QUAD_CurrentVersionRun_7294 {
  strings:
    $key_7294 = { 21 fb [2] 05 f5 [2] 2e d9 [2] 00 fb [2] 14 e0 [2] 1b fa [2] 05 e7 [2] 07 e6 [2] 1c e0 [2] 00 e7 [2] 1c c8 }

  condition:
    any of them
}