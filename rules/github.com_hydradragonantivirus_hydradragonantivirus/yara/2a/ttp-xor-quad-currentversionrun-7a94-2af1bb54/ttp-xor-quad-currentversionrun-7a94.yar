rule TTP_XOR_QUAD_CurrentVersionRun_7a94 {
  strings:
    $key_7a94 = { 29 fb [2] 0d f5 [2] 26 d9 [2] 08 fb [2] 1c e0 [2] 13 fa [2] 0d e7 [2] 0f e6 [2] 14 e0 [2] 08 e7 [2] 14 c8 }

  condition:
    any of them
}