rule TTP_XOR_QUAD_CurrentVersionRun_3f89 {
  strings:
    $key_3f89 = { 6c e6 [2] 48 e8 [2] 63 c4 [2] 4d e6 [2] 59 fd [2] 56 e7 [2] 48 fa [2] 4a fb [2] 51 fd [2] 4d fa [2] 51 d5 }

  condition:
    any of them
}