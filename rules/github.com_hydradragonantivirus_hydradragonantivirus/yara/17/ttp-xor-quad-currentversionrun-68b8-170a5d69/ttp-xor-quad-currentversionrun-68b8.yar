rule TTP_XOR_QUAD_CurrentVersionRun_68b8 {
  strings:
    $key_68b8 = { 3b d7 [2] 1f d9 [2] 34 f5 [2] 1a d7 [2] 0e cc [2] 01 d6 [2] 1f cb [2] 1d ca [2] 06 cc [2] 1a cb [2] 06 e4 }

  condition:
    any of them
}