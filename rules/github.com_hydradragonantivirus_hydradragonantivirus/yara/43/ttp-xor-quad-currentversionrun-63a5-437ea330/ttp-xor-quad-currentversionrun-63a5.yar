rule TTP_XOR_QUAD_CurrentVersionRun_63a5 {
  strings:
    $key_63a5 = { 30 ca [2] 14 c4 [2] 3f e8 [2] 11 ca [2] 05 d1 [2] 0a cb [2] 14 d6 [2] 16 d7 [2] 0d d1 [2] 11 d6 [2] 0d f9 }

  condition:
    any of them
}