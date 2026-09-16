rule TTP_XOR_QUAD_CurrentVersionRun_1b94 {
  strings:
    $key_1b94 = { 48 fb [2] 6c f5 [2] 47 d9 [2] 69 fb [2] 7d e0 [2] 72 fa [2] 6c e7 [2] 6e e6 [2] 75 e0 [2] 69 e7 [2] 75 c8 }

  condition:
    any of them
}