rule TTP_XOR_QUAD_CurrentVersionRun_7395 {
  strings:
    $key_7395 = { 20 fa [2] 04 f4 [2] 2f d8 [2] 01 fa [2] 15 e1 [2] 1a fb [2] 04 e6 [2] 06 e7 [2] 1d e1 [2] 01 e6 [2] 1d c9 }

  condition:
    any of them
}