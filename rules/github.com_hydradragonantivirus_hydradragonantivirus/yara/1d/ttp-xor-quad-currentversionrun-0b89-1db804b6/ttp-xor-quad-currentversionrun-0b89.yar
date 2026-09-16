rule TTP_XOR_QUAD_CurrentVersionRun_0b89 {
  strings:
    $key_0b89 = { 58 e6 [2] 7c e8 [2] 57 c4 [2] 79 e6 [2] 6d fd [2] 62 e7 [2] 7c fa [2] 7e fb [2] 65 fd [2] 79 fa [2] 65 d5 }

  condition:
    any of them
}