rule TTP_XOR_QUAD_CurrentVersionRun_04b7 {
  strings:
    $key_04b7 = { 57 d8 [2] 73 d6 [2] 58 fa [2] 76 d8 [2] 62 c3 [2] 6d d9 [2] 73 c4 [2] 71 c5 [2] 6a c3 [2] 76 c4 [2] 6a eb }

  condition:
    any of them
}