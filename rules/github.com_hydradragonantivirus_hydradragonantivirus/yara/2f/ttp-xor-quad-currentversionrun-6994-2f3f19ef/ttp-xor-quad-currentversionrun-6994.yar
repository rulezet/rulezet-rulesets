rule TTP_XOR_QUAD_CurrentVersionRun_6994 {
  strings:
    $key_6994 = { 3a fb [2] 1e f5 [2] 35 d9 [2] 1b fb [2] 0f e0 [2] 00 fa [2] 1e e7 [2] 1c e6 [2] 07 e0 [2] 1b e7 [2] 07 c8 }

  condition:
    any of them
}