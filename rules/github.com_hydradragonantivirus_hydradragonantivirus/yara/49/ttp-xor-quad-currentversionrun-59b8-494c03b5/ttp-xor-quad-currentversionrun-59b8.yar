rule TTP_XOR_QUAD_CurrentVersionRun_59b8 {
  strings:
    $key_59b8 = { 0a d7 [2] 2e d9 [2] 05 f5 [2] 2b d7 [2] 3f cc [2] 30 d6 [2] 2e cb [2] 2c ca [2] 37 cc [2] 2b cb [2] 37 e4 }

  condition:
    any of them
}