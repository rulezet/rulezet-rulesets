rule TTP_XOR_QUAD_CurrentVersionRun_2ca4 {
  strings:
    $key_2ca4 = { 7f cb [2] 5b c5 [2] 70 e9 [2] 5e cb [2] 4a d0 [2] 45 ca [2] 5b d7 [2] 59 d6 [2] 42 d0 [2] 5e d7 [2] 42 f8 }

  condition:
    any of them
}