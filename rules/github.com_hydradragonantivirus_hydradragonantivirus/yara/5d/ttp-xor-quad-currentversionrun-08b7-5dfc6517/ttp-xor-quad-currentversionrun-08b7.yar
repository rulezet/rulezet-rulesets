rule TTP_XOR_QUAD_CurrentVersionRun_08b7 {
  strings:
    $key_08b7 = { 5b d8 [2] 7f d6 [2] 54 fa [2] 7a d8 [2] 6e c3 [2] 61 d9 [2] 7f c4 [2] 7d c5 [2] 66 c3 [2] 7a c4 [2] 66 eb }

  condition:
    any of them
}