rule TTP_XOR_QUAD_CurrentVersionRun_6ca4 {
  strings:
    $key_6ca4 = { 3f cb [2] 1b c5 [2] 30 e9 [2] 1e cb [2] 0a d0 [2] 05 ca [2] 1b d7 [2] 19 d6 [2] 02 d0 [2] 1e d7 [2] 02 f8 }

  condition:
    any of them
}