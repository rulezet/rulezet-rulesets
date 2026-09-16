rule TTP_XOR_QUAD_CurrentVersionRun_e8b8 {
  strings:
    $key_e8b8 = { bb d7 [2] 9f d9 [2] b4 f5 [2] 9a d7 [2] 8e cc [2] 81 d6 [2] 9f cb [2] 9d ca [2] 86 cc [2] 9a cb [2] 86 e4 }

  condition:
    any of them
}