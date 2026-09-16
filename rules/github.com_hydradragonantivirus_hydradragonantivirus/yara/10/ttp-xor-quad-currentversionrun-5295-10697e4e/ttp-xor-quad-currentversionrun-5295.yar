rule TTP_XOR_QUAD_CurrentVersionRun_5295 {
  strings:
    $key_5295 = { 01 fa [2] 25 f4 [2] 0e d8 [2] 20 fa [2] 34 e1 [2] 3b fb [2] 25 e6 [2] 27 e7 [2] 3c e1 [2] 20 e6 [2] 3c c9 }

  condition:
    any of them
}