rule TTP_XOR_QUAD_CurrentVersionRun_1089 {
  strings:
    $key_1089 = { 43 e6 [2] 67 e8 [2] 4c c4 [2] 62 e6 [2] 76 fd [2] 79 e7 [2] 67 fa [2] 65 fb [2] 7e fd [2] 62 fa [2] 7e d5 }

  condition:
    any of them
}