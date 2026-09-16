rule TTP_XOR_QUAD_CurrentVersionRun_2da4 {
  strings:
    $key_2da4 = { 7e cb [2] 5a c5 [2] 71 e9 [2] 5f cb [2] 4b d0 [2] 44 ca [2] 5a d7 [2] 58 d6 [2] 43 d0 [2] 5f d7 [2] 43 f8 }

  condition:
    any of them
}