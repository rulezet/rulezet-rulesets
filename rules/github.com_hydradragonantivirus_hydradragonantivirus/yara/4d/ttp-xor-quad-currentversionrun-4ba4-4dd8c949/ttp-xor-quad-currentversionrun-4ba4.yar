rule TTP_XOR_QUAD_CurrentVersionRun_4ba4 {
  strings:
    $key_4ba4 = { 18 cb [2] 3c c5 [2] 17 e9 [2] 39 cb [2] 2d d0 [2] 22 ca [2] 3c d7 [2] 3e d6 [2] 25 d0 [2] 39 d7 [2] 25 f8 }

  condition:
    any of them
}