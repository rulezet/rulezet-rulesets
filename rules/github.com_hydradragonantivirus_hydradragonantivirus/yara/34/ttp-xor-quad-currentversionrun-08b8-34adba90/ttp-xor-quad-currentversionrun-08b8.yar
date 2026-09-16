rule TTP_XOR_QUAD_CurrentVersionRun_08b8 {
  strings:
    $key_08b8 = { 5b d7 [2] 7f d9 [2] 54 f5 [2] 7a d7 [2] 6e cc [2] 61 d6 [2] 7f cb [2] 7d ca [2] 66 cc [2] 7a cb [2] 66 e4 }

  condition:
    any of them
}