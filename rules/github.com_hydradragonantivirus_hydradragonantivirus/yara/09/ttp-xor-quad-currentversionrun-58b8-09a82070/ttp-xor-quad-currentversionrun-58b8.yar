rule TTP_XOR_QUAD_CurrentVersionRun_58b8 {
  strings:
    $key_58b8 = { 0b d7 [2] 2f d9 [2] 04 f5 [2] 2a d7 [2] 3e cc [2] 31 d6 [2] 2f cb [2] 2d ca [2] 36 cc [2] 2a cb [2] 36 e4 }

  condition:
    any of them
}