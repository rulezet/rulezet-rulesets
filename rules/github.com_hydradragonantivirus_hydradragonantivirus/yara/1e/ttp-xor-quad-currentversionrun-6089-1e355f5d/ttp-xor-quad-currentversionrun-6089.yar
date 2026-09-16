rule TTP_XOR_QUAD_CurrentVersionRun_6089 {
  strings:
    $key_6089 = { 33 e6 [2] 17 e8 [2] 3c c4 [2] 12 e6 [2] 06 fd [2] 09 e7 [2] 17 fa [2] 15 fb [2] 0e fd [2] 12 fa [2] 0e d5 }

  condition:
    any of them
}