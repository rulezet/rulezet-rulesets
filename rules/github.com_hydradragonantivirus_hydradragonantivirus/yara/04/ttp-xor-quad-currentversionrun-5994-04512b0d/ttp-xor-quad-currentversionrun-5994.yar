rule TTP_XOR_QUAD_CurrentVersionRun_5994 {
  strings:
    $key_5994 = { 0a fb [2] 2e f5 [2] 05 d9 [2] 2b fb [2] 3f e0 [2] 30 fa [2] 2e e7 [2] 2c e6 [2] 37 e0 [2] 2b e7 [2] 37 c8 }

  condition:
    any of them
}