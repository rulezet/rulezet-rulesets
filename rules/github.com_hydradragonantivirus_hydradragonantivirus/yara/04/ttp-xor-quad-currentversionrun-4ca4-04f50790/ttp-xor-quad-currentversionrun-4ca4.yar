rule TTP_XOR_QUAD_CurrentVersionRun_4ca4 {
  strings:
    $key_4ca4 = { 1f cb [2] 3b c5 [2] 10 e9 [2] 3e cb [2] 2a d0 [2] 25 ca [2] 3b d7 [2] 39 d6 [2] 22 d0 [2] 3e d7 [2] 22 f8 }

  condition:
    any of them
}