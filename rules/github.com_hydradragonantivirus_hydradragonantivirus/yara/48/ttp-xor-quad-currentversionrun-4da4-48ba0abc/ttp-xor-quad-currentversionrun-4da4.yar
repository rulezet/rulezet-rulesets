rule TTP_XOR_QUAD_CurrentVersionRun_4da4 {
  strings:
    $key_4da4 = { 1e cb [2] 3a c5 [2] 11 e9 [2] 3f cb [2] 2b d0 [2] 24 ca [2] 3a d7 [2] 38 d6 [2] 23 d0 [2] 3f d7 [2] 23 f8 }

  condition:
    any of them
}