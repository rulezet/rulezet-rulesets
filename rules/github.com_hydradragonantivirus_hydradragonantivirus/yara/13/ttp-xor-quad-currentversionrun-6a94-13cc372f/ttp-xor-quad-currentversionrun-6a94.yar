rule TTP_XOR_QUAD_CurrentVersionRun_6a94 {
  strings:
    $key_6a94 = { 39 fb [2] 1d f5 [2] 36 d9 [2] 18 fb [2] 0c e0 [2] 03 fa [2] 1d e7 [2] 1f e6 [2] 04 e0 [2] 18 e7 [2] 04 c8 }

  condition:
    any of them
}