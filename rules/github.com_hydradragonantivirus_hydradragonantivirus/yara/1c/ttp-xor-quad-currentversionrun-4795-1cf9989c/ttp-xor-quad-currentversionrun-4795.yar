rule TTP_XOR_QUAD_CurrentVersionRun_4795 {
  strings:
    $key_4795 = { 14 fa [2] 30 f4 [2] 1b d8 [2] 35 fa [2] 21 e1 [2] 2e fb [2] 30 e6 [2] 32 e7 [2] 29 e1 [2] 35 e6 [2] 29 c9 }

  condition:
    any of them
}