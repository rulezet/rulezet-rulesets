rule TTP_XOR_QUAD_CurrentVersionRun_3a94 {
  strings:
    $key_3a94 = { 69 fb [2] 4d f5 [2] 66 d9 [2] 48 fb [2] 5c e0 [2] 53 fa [2] 4d e7 [2] 4f e6 [2] 54 e0 [2] 48 e7 [2] 54 c8 }

  condition:
    any of them
}