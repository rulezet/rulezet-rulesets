rule TTP_XOR_QUAD_CurrentVersionRun_54b7 {
  strings:
    $key_54b7 = { 07 d8 [2] 23 d6 [2] 08 fa [2] 26 d8 [2] 32 c3 [2] 3d d9 [2] 23 c4 [2] 21 c5 [2] 3a c3 [2] 26 c4 [2] 3a eb }

  condition:
    any of them
}