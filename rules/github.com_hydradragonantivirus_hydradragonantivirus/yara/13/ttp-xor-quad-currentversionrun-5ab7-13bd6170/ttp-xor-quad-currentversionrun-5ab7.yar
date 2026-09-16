rule TTP_XOR_QUAD_CurrentVersionRun_5ab7 {
  strings:
    $key_5ab7 = { 09 d8 [2] 2d d6 [2] 06 fa [2] 28 d8 [2] 3c c3 [2] 33 d9 [2] 2d c4 [2] 2f c5 [2] 34 c3 [2] 28 c4 [2] 34 eb }

  condition:
    any of them
}