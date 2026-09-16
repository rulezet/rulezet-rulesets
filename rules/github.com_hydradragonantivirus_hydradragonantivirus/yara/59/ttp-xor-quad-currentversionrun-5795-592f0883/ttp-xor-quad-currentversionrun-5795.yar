rule TTP_XOR_QUAD_CurrentVersionRun_5795 {
  strings:
    $key_5795 = { 04 fa [2] 20 f4 [2] 0b d8 [2] 25 fa [2] 31 e1 [2] 3e fb [2] 20 e6 [2] 22 e7 [2] 39 e1 [2] 25 e6 [2] 39 c9 }

  condition:
    any of them
}