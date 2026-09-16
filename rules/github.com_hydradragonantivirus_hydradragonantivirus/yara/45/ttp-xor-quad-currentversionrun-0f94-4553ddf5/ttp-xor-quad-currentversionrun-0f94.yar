rule TTP_XOR_QUAD_CurrentVersionRun_0f94 {
  strings:
    $key_0f94 = { 5c fb [2] 78 f5 [2] 53 d9 [2] 7d fb [2] 69 e0 [2] 66 fa [2] 78 e7 [2] 7a e6 [2] 61 e0 [2] 7d e7 [2] 61 c8 }

  condition:
    any of them
}