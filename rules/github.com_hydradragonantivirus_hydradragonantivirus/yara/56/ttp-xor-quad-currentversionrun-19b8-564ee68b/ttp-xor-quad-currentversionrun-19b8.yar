rule TTP_XOR_QUAD_CurrentVersionRun_19b8 {
  strings:
    $key_19b8 = { 4a d7 [2] 6e d9 [2] 45 f5 [2] 6b d7 [2] 7f cc [2] 70 d6 [2] 6e cb [2] 6c ca [2] 77 cc [2] 6b cb [2] 77 e4 }

  condition:
    any of them
}