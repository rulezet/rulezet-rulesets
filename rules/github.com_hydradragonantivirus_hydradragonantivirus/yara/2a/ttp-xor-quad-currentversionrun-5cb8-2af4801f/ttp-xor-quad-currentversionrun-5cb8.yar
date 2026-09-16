rule TTP_XOR_QUAD_CurrentVersionRun_5cb8 {
  strings:
    $key_5cb8 = { 0f d7 [2] 2b d9 [2] 00 f5 [2] 2e d7 [2] 3a cc [2] 35 d6 [2] 2b cb [2] 29 ca [2] 32 cc [2] 2e cb [2] 32 e4 }

  condition:
    any of them
}