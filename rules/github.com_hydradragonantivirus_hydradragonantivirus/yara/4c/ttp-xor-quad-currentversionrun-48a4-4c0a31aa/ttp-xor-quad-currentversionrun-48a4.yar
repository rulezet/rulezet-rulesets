rule TTP_XOR_QUAD_CurrentVersionRun_48a4 {
  strings:
    $key_48a4 = { 1b cb [2] 3f c5 [2] 14 e9 [2] 3a cb [2] 2e d0 [2] 21 ca [2] 3f d7 [2] 3d d6 [2] 26 d0 [2] 3a d7 [2] 26 f8 }

  condition:
    any of them
}