rule TTP_XOR_QUAD_CurrentVersionRun_fa94 {
  strings:
    $key_fa94 = { a9 fb [2] 8d f5 [2] a6 d9 [2] 88 fb [2] 9c e0 [2] 93 fa [2] 8d e7 [2] 8f e6 [2] 94 e0 [2] 88 e7 [2] 94 c8 }

  condition:
    any of them
}