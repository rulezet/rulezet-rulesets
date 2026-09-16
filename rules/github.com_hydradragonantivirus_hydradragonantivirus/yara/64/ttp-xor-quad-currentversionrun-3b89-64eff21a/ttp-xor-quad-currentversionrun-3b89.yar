rule TTP_XOR_QUAD_CurrentVersionRun_3b89 {
  strings:
    $key_3b89 = { 68 e6 [2] 4c e8 [2] 67 c4 [2] 49 e6 [2] 5d fd [2] 52 e7 [2] 4c fa [2] 4e fb [2] 55 fd [2] 49 fa [2] 55 d5 }

  condition:
    any of them
}