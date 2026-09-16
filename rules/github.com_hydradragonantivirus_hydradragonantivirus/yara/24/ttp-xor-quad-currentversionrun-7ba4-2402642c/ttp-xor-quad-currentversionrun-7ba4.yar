rule TTP_XOR_QUAD_CurrentVersionRun_7ba4 {
  strings:
    $key_7ba4 = { 28 cb [2] 0c c5 [2] 27 e9 [2] 09 cb [2] 1d d0 [2] 12 ca [2] 0c d7 [2] 0e d6 [2] 15 d0 [2] 09 d7 [2] 15 f8 }

  condition:
    any of them
}