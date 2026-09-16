rule TTP_XOR_QUAD_CurrentVersionRun_6695 {
  strings:
    $key_6695 = { 35 fa [2] 11 f4 [2] 3a d8 [2] 14 fa [2] 00 e1 [2] 0f fb [2] 11 e6 [2] 13 e7 [2] 08 e1 [2] 14 e6 [2] 08 c9 }

  condition:
    any of them
}