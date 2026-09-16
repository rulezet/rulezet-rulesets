rule TTP_XOR_QUAD_CurrentVersionRun_64b7 {
  strings:
    $key_64b7 = { 37 d8 [2] 13 d6 [2] 38 fa [2] 16 d8 [2] 02 c3 [2] 0d d9 [2] 13 c4 [2] 11 c5 [2] 0a c3 [2] 16 c4 [2] 0a eb }

  condition:
    any of them
}