rule TTP_XOR_QUAD_CurrentVersionRun_f8b8 {
  strings:
    $key_f8b8 = { ab d7 [2] 8f d9 [2] a4 f5 [2] 8a d7 [2] 9e cc [2] 91 d6 [2] 8f cb [2] 8d ca [2] 96 cc [2] 8a cb [2] 96 e4 }

  condition:
    any of them
}