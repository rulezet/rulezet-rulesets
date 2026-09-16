rule TTP_XOR_QUAD_CurrentVersionRun_fba5 {
  strings:
    $key_fba5 = { a8 ca [2] 8c c4 [2] a7 e8 [2] 89 ca [2] 9d d1 [2] 92 cb [2] 8c d6 [2] 8e d7 [2] 95 d1 [2] 89 d6 [2] 95 f9 }

  condition:
    any of them
}