rule TTP_XOR_QUAD_CurrentVersionRun_2795 {
  strings:
    $key_2795 = { 74 fa [2] 50 f4 [2] 7b d8 [2] 55 fa [2] 41 e1 [2] 4e fb [2] 50 e6 [2] 52 e7 [2] 49 e1 [2] 55 e6 [2] 49 c9 }

  condition:
    any of them
}