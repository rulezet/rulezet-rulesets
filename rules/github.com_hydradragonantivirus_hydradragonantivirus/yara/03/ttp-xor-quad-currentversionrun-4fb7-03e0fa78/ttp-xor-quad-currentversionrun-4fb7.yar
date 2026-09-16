rule TTP_XOR_QUAD_CurrentVersionRun_4fb7 {
  strings:
    $key_4fb7 = { 1c d8 [2] 38 d6 [2] 13 fa [2] 3d d8 [2] 29 c3 [2] 26 d9 [2] 38 c4 [2] 3a c5 [2] 21 c3 [2] 3d c4 [2] 21 eb }

  condition:
    any of them
}