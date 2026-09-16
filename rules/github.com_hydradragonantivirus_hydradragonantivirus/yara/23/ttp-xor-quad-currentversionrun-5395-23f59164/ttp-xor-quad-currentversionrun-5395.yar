rule TTP_XOR_QUAD_CurrentVersionRun_5395 {
  strings:
    $key_5395 = { 00 fa [2] 24 f4 [2] 0f d8 [2] 21 fa [2] 35 e1 [2] 3a fb [2] 24 e6 [2] 26 e7 [2] 3d e1 [2] 21 e6 [2] 3d c9 }

  condition:
    any of them
}