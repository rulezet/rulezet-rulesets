rule TTP_XOR_QUAD_CurrentVersionRun_79a4 {
  strings:
    $key_79a4 = { 2a cb [2] 0e c5 [2] 25 e9 [2] 0b cb [2] 1f d0 [2] 10 ca [2] 0e d7 [2] 0c d6 [2] 17 d0 [2] 0b d7 [2] 17 f8 }

  condition:
    any of them
}