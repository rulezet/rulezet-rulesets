rule TTP_XOR_QUAD_CurrentVersionRun_23a5 {
  strings:
    $key_23a5 = { 70 ca [2] 54 c4 [2] 7f e8 [2] 51 ca [2] 45 d1 [2] 4a cb [2] 54 d6 [2] 56 d7 [2] 4d d1 [2] 51 d6 [2] 4d f9 }

  condition:
    any of them
}