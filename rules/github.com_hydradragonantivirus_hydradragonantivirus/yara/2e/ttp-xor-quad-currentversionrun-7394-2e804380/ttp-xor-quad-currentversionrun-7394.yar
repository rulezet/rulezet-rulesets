rule TTP_XOR_QUAD_CurrentVersionRun_7394 {
  strings:
    $key_7394 = { 20 fb [2] 04 f5 [2] 2f d9 [2] 01 fb [2] 15 e0 [2] 1a fa [2] 04 e7 [2] 06 e6 [2] 1d e0 [2] 01 e7 [2] 1d c8 }

  condition:
    any of them
}