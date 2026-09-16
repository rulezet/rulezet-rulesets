rule TTP_XOR_QUAD_CurrentVersionRun_5a89 {
  strings:
    $key_5a89 = { 09 e6 [2] 2d e8 [2] 06 c4 [2] 28 e6 [2] 3c fd [2] 33 e7 [2] 2d fa [2] 2f fb [2] 34 fd [2] 28 fa [2] 34 d5 }

  condition:
    any of them
}