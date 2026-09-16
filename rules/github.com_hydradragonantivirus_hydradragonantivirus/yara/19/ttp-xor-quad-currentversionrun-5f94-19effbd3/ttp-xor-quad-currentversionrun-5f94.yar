rule TTP_XOR_QUAD_CurrentVersionRun_5f94 {
  strings:
    $key_5f94 = { 0c fb [2] 28 f5 [2] 03 d9 [2] 2d fb [2] 39 e0 [2] 36 fa [2] 28 e7 [2] 2a e6 [2] 31 e0 [2] 2d e7 [2] 31 c8 }

  condition:
    any of them
}