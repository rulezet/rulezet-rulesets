rule TTP_XOR_QUAD_CurrentVersionRun_2a89 {
  strings:
    $key_2a89 = { 79 e6 [2] 5d e8 [2] 76 c4 [2] 58 e6 [2] 4c fd [2] 43 e7 [2] 5d fa [2] 5f fb [2] 44 fd [2] 58 fa [2] 44 d5 }

  condition:
    any of them
}