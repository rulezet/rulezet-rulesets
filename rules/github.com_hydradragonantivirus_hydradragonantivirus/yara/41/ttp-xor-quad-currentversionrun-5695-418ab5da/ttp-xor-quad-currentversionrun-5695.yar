rule TTP_XOR_QUAD_CurrentVersionRun_5695 {
  strings:
    $key_5695 = { 05 fa [2] 21 f4 [2] 0a d8 [2] 24 fa [2] 30 e1 [2] 3f fb [2] 21 e6 [2] 23 e7 [2] 38 e1 [2] 24 e6 [2] 38 c9 }

  condition:
    any of them
}