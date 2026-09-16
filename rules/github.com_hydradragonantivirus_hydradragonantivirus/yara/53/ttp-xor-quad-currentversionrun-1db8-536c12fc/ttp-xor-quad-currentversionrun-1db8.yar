rule TTP_XOR_QUAD_CurrentVersionRun_1db8 {
  strings:
    $key_1db8 = { 4e d7 [2] 6a d9 [2] 41 f5 [2] 6f d7 [2] 7b cc [2] 74 d6 [2] 6a cb [2] 68 ca [2] 73 cc [2] 6f cb [2] 73 e4 }

  condition:
    any of them
}