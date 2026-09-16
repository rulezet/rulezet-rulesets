rule TTP_XOR_QUAD_CurrentVersionRun_48b7 {
  strings:
    $key_48b7 = { 1b d8 [2] 3f d6 [2] 14 fa [2] 3a d8 [2] 2e c3 [2] 21 d9 [2] 3f c4 [2] 3d c5 [2] 26 c3 [2] 3a c4 [2] 26 eb }

  condition:
    any of them
}