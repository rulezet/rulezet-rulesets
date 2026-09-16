rule TTP_XOR_QUAD_CurrentVersionRun_2789 {
  strings:
    $key_2789 = { 74 e6 [2] 50 e8 [2] 7b c4 [2] 55 e6 [2] 41 fd [2] 4e e7 [2] 50 fa [2] 52 fb [2] 49 fd [2] 55 fa [2] 49 d5 }

  condition:
    any of them
}