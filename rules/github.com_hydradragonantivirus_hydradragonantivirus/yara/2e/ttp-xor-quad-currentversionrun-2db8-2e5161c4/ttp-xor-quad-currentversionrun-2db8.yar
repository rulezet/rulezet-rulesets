rule TTP_XOR_QUAD_CurrentVersionRun_2db8 {
  strings:
    $key_2db8 = { 7e d7 [2] 5a d9 [2] 71 f5 [2] 5f d7 [2] 4b cc [2] 44 d6 [2] 5a cb [2] 58 ca [2] 43 cc [2] 5f cb [2] 43 e4 }

  condition:
    any of them
}