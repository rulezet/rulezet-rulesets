rule TTP_XOR_QUAD_CurrentVersionRun_4cb8 {
  strings:
    $key_4cb8 = { 1f d7 [2] 3b d9 [2] 10 f5 [2] 3e d7 [2] 2a cc [2] 25 d6 [2] 3b cb [2] 39 ca [2] 22 cc [2] 3e cb [2] 22 e4 }

  condition:
    any of them
}