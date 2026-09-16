rule TTP_XOR_QUAD_CurrentVersionRun_4cb7 {
  strings:
    $key_4cb7 = { 1f d8 [2] 3b d6 [2] 10 fa [2] 3e d8 [2] 2a c3 [2] 25 d9 [2] 3b c4 [2] 39 c5 [2] 22 c3 [2] 3e c4 [2] 22 eb }

  condition:
    any of them
}