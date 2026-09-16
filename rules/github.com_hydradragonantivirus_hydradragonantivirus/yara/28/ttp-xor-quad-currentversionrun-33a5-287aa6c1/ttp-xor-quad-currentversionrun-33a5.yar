rule TTP_XOR_QUAD_CurrentVersionRun_33a5 {
  strings:
    $key_33a5 = { 60 ca [2] 44 c4 [2] 6f e8 [2] 41 ca [2] 55 d1 [2] 5a cb [2] 44 d6 [2] 46 d7 [2] 5d d1 [2] 41 d6 [2] 5d f9 }

  condition:
    any of them
}