rule TTP_XOR_QUAD_CurrentVersionRun_78b7 {
  strings:
    $key_78b7 = { 2b d8 [2] 0f d6 [2] 24 fa [2] 0a d8 [2] 1e c3 [2] 11 d9 [2] 0f c4 [2] 0d c5 [2] 16 c3 [2] 0a c4 [2] 16 eb }

  condition:
    any of them
}