rule TTP_XOR_QUAD_CurrentVersionRun_7f89 {
  strings:
    $key_7f89 = { 2c e6 [2] 08 e8 [2] 23 c4 [2] 0d e6 [2] 19 fd [2] 16 e7 [2] 08 fa [2] 0a fb [2] 11 fd [2] 0d fa [2] 11 d5 }

  condition:
    any of them
}