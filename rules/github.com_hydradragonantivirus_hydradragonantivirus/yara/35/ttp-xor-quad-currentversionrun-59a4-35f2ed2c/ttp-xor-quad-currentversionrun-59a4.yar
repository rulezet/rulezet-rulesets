rule TTP_XOR_QUAD_CurrentVersionRun_59a4 {
  strings:
    $key_59a4 = { 0a cb [2] 2e c5 [2] 05 e9 [2] 2b cb [2] 3f d0 [2] 30 ca [2] 2e d7 [2] 2c d6 [2] 37 d0 [2] 2b d7 [2] 37 f8 }

  condition:
    any of them
}