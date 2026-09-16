rule TTP_XOR_QUAD_CurrentVersionRun_0f89 {
  strings:
    $key_0f89 = { 5c e6 [2] 78 e8 [2] 53 c4 [2] 7d e6 [2] 69 fd [2] 66 e7 [2] 78 fa [2] 7a fb [2] 61 fd [2] 7d fa [2] 61 d5 }

  condition:
    any of them
}