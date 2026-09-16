rule TTP_XOR_QUAD_CurrentVersionRun_ecb8 {
  strings:
    $key_ecb8 = { bf d7 [2] 9b d9 [2] b0 f5 [2] 9e d7 [2] 8a cc [2] 85 d6 [2] 9b cb [2] 99 ca [2] 82 cc [2] 9e cb [2] 82 e4 }

  condition:
    any of them
}