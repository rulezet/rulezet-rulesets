rule TTP_XOR_QUAD_CurrentVersionRun_4f89 {
  strings:
    $key_4f89 = { 1c e6 [2] 38 e8 [2] 13 c4 [2] 3d e6 [2] 29 fd [2] 26 e7 [2] 38 fa [2] 3a fb [2] 21 fd [2] 3d fa [2] 21 d5 }

  condition:
    any of them
}