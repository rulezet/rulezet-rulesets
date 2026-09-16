rule TTP_XOR_QUAD_CurrentVersionRun_74b8 {
  strings:
    $key_74b8 = { 27 d7 [2] 03 d9 [2] 28 f5 [2] 06 d7 [2] 12 cc [2] 1d d6 [2] 03 cb [2] 01 ca [2] 1a cc [2] 06 cb [2] 1a e4 }

  condition:
    any of them
}