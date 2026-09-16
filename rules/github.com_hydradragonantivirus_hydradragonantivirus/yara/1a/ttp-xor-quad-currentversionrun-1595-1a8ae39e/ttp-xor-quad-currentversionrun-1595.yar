rule TTP_XOR_QUAD_CurrentVersionRun_1595 {
  strings:
    $key_1595 = { 46 fa [2] 62 f4 [2] 49 d8 [2] 67 fa [2] 73 e1 [2] 7c fb [2] 62 e6 [2] 60 e7 [2] 7b e1 [2] 67 e6 [2] 7b c9 }

  condition:
    any of them
}