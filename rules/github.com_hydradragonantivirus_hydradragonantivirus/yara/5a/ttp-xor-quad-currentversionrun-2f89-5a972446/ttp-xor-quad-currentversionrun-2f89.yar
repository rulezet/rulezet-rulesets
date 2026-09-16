rule TTP_XOR_QUAD_CurrentVersionRun_2f89 {
  strings:
    $key_2f89 = { 7c e6 [2] 58 e8 [2] 73 c4 [2] 5d e6 [2] 49 fd [2] 46 e7 [2] 58 fa [2] 5a fb [2] 41 fd [2] 5d fa [2] 41 d5 }

  condition:
    any of them
}