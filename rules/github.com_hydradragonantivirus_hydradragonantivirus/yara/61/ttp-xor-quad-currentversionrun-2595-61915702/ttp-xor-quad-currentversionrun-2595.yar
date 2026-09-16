rule TTP_XOR_QUAD_CurrentVersionRun_2595 {
  strings:
    $key_2595 = { 76 fa [2] 52 f4 [2] 79 d8 [2] 57 fa [2] 43 e1 [2] 4c fb [2] 52 e6 [2] 50 e7 [2] 4b e1 [2] 57 e6 [2] 4b c9 }

  condition:
    any of them
}