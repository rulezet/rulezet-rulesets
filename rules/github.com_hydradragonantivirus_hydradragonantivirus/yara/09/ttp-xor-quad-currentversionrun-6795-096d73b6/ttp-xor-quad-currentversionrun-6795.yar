rule TTP_XOR_QUAD_CurrentVersionRun_6795 {
  strings:
    $key_6795 = { 34 fa [2] 10 f4 [2] 3b d8 [2] 15 fa [2] 01 e1 [2] 0e fb [2] 10 e6 [2] 12 e7 [2] 09 e1 [2] 15 e6 [2] 09 c9 }

  condition:
    any of them
}