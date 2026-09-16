rule TTP_XOR_QUAD_CurrentVersionRun_1cb8 {
  strings:
    $key_1cb8 = { 4f d7 [2] 6b d9 [2] 40 f5 [2] 6e d7 [2] 7a cc [2] 75 d6 [2] 6b cb [2] 69 ca [2] 72 cc [2] 6e cb [2] 72 e4 }

  condition:
    any of them
}