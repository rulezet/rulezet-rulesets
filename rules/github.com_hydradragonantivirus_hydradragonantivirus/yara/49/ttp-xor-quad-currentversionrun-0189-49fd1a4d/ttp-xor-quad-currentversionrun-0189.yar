rule TTP_XOR_QUAD_CurrentVersionRun_0189 {
  strings:
    $key_0189 = { 52 e6 [2] 76 e8 [2] 5d c4 [2] 73 e6 [2] 67 fd [2] 68 e7 [2] 76 fa [2] 74 fb [2] 6f fd [2] 73 fa [2] 6f d5 }

  condition:
    any of them
}