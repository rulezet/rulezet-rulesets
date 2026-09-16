rule TTP_XOR_QUAD_CurrentVersionRun_68b7 {
  strings:
    $key_68b7 = { 3b d8 [2] 1f d6 [2] 34 fa [2] 1a d8 [2] 0e c3 [2] 01 d9 [2] 1f c4 [2] 1d c5 [2] 06 c3 [2] 1a c4 [2] 06 eb }

  condition:
    any of them
}