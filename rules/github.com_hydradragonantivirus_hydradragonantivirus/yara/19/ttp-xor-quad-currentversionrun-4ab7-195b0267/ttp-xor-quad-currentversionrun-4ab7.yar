rule TTP_XOR_QUAD_CurrentVersionRun_4ab7 {
  strings:
    $key_4ab7 = { 19 d8 [2] 3d d6 [2] 16 fa [2] 38 d8 [2] 2c c3 [2] 23 d9 [2] 3d c4 [2] 3f c5 [2] 24 c3 [2] 38 c4 [2] 24 eb }

  condition:
    any of them
}