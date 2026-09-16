rule TTP_XOR_QUAD_CurrentVersionRun_4b94 {
  strings:
    $key_4b94 = { 18 fb [2] 3c f5 [2] 17 d9 [2] 39 fb [2] 2d e0 [2] 22 fa [2] 3c e7 [2] 3e e6 [2] 25 e0 [2] 39 e7 [2] 25 c8 }

  condition:
    any of them
}