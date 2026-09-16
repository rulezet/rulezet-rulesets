rule TTP_XOR_QUAD_CurrentVersionRun_1f94 {
  strings:
    $key_1f94 = { 4c fb [2] 68 f5 [2] 43 d9 [2] 6d fb [2] 79 e0 [2] 76 fa [2] 68 e7 [2] 6a e6 [2] 71 e0 [2] 6d e7 [2] 71 c8 }

  condition:
    any of them
}