rule TTP_XOR_QUAD_CurrentVersionRun_29b8 {
  strings:
    $key_29b8 = { 7a d7 [2] 5e d9 [2] 75 f5 [2] 5b d7 [2] 4f cc [2] 40 d6 [2] 5e cb [2] 5c ca [2] 47 cc [2] 5b cb [2] 47 e4 }

  condition:
    any of them
}