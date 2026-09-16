rule TTP_XOR_QUAD_CurrentVersionRun_4f94 {
  strings:
    $key_4f94 = { 1c fb [2] 38 f5 [2] 13 d9 [2] 3d fb [2] 29 e0 [2] 26 fa [2] 38 e7 [2] 3a e6 [2] 21 e0 [2] 3d e7 [2] 21 c8 }

  condition:
    any of them
}