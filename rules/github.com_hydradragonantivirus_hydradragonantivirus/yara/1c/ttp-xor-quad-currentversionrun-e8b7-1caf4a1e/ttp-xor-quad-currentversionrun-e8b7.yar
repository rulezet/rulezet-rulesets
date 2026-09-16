rule TTP_XOR_QUAD_CurrentVersionRun_e8b7 {
  strings:
    $key_e8b7 = { bb d8 [2] 9f d6 [2] b4 fa [2] 9a d8 [2] 8e c3 [2] 81 d9 [2] 9f c4 [2] 9d c5 [2] 86 c3 [2] 9a c4 [2] 86 eb }

  condition:
    any of them
}