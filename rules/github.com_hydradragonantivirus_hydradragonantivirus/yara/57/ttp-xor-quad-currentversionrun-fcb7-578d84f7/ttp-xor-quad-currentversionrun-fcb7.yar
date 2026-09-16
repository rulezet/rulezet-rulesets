rule TTP_XOR_QUAD_CurrentVersionRun_fcb7 {
  strings:
    $key_fcb7 = { af d8 [2] 8b d6 [2] a0 fa [2] 8e d8 [2] 9a c3 [2] 95 d9 [2] 8b c4 [2] 89 c5 [2] 92 c3 [2] 8e c4 [2] 92 eb }

  condition:
    any of them
}