rule TTP_XOR_QUAD_CurrentVersionRun_6f94 {
  strings:
    $key_6f94 = { 3c fb [2] 18 f5 [2] 33 d9 [2] 1d fb [2] 09 e0 [2] 06 fa [2] 18 e7 [2] 1a e6 [2] 01 e0 [2] 1d e7 [2] 01 c8 }

  condition:
    any of them
}