rule TTP_XOR_QUAD_CurrentVersionRun_39b8 {
  strings:
    $key_39b8 = { 6a d7 [2] 4e d9 [2] 65 f5 [2] 4b d7 [2] 5f cc [2] 50 d6 [2] 4e cb [2] 4c ca [2] 57 cc [2] 4b cb [2] 57 e4 }

  condition:
    any of them
}