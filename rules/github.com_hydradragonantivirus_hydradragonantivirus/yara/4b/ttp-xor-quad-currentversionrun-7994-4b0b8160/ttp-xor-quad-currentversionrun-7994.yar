rule TTP_XOR_QUAD_CurrentVersionRun_7994 {
  strings:
    $key_7994 = { 2a fb [2] 0e f5 [2] 25 d9 [2] 0b fb [2] 1f e0 [2] 10 fa [2] 0e e7 [2] 0c e6 [2] 17 e0 [2] 0b e7 [2] 17 c8 }

  condition:
    any of them
}