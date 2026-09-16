rule TTP_XOR_QUAD_CurrentVersionRun_fdb7 {
  strings:
    $key_fdb7 = { ae d8 [2] 8a d6 [2] a1 fa [2] 8f d8 [2] 9b c3 [2] 94 d9 [2] 8a c4 [2] 88 c5 [2] 93 c3 [2] 8f c4 [2] 93 eb }

  condition:
    any of them
}