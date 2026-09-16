rule TTP_XOR_QUAD_CurrentVersionRun_74a5 {
  strings:
    $key_74a5 = { 27 ca [2] 03 c4 [2] 28 e8 [2] 06 ca [2] 12 d1 [2] 1d cb [2] 03 d6 [2] 01 d7 [2] 1a d1 [2] 06 d6 [2] 1a f9 }

  condition:
    any of them
}