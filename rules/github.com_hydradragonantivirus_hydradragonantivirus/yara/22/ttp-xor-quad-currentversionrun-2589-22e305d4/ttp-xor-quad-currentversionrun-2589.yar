rule TTP_XOR_QUAD_CurrentVersionRun_2589 {
  strings:
    $key_2589 = { 76 e6 [2] 52 e8 [2] 79 c4 [2] 57 e6 [2] 43 fd [2] 4c e7 [2] 52 fa [2] 50 fb [2] 4b fd [2] 57 fa [2] 4b d5 }

  condition:
    any of them
}