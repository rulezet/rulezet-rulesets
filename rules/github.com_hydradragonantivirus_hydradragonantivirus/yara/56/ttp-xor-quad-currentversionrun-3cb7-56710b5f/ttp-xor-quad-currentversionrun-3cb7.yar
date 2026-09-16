rule TTP_XOR_QUAD_CurrentVersionRun_3cb7 {
  strings:
    $key_3cb7 = { 6f d8 [2] 4b d6 [2] 60 fa [2] 4e d8 [2] 5a c3 [2] 55 d9 [2] 4b c4 [2] 49 c5 [2] 52 c3 [2] 4e c4 [2] 52 eb }

  condition:
    any of them
}