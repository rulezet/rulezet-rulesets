rule TTP_XOR_QUAD_CurrentVersionRun_18a4 {
  strings:
    $key_18a4 = { 4b cb [2] 6f c5 [2] 44 e9 [2] 6a cb [2] 7e d0 [2] 71 ca [2] 6f d7 [2] 6d d6 [2] 76 d0 [2] 6a d7 [2] 76 f8 }

  condition:
    any of them
}