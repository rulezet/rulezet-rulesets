rule TTP_XOR_QUAD_CurrentVersionRun_73a5 {
  strings:
    $key_73a5 = { 20 ca [2] 04 c4 [2] 2f e8 [2] 01 ca [2] 15 d1 [2] 1a cb [2] 04 d6 [2] 06 d7 [2] 1d d1 [2] 01 d6 [2] 1d f9 }

  condition:
    any of them
}