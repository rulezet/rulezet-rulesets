rule TTP_XOR_QUAD_CurrentVersionRun_49b8 {
  strings:
    $key_49b8 = { 1a d7 [2] 3e d9 [2] 15 f5 [2] 3b d7 [2] 2f cc [2] 20 d6 [2] 3e cb [2] 3c ca [2] 27 cc [2] 3b cb [2] 27 e4 }

  condition:
    any of them
}