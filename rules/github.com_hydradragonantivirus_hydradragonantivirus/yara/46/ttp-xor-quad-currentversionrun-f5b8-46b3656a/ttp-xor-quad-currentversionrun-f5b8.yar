rule TTP_XOR_QUAD_CurrentVersionRun_f5b8 {
  strings:
    $key_f5b8 = { a6 d7 [2] 82 d9 [2] a9 f5 [2] 87 d7 [2] 93 cc [2] 9c d6 [2] 82 cb [2] 80 ca [2] 9b cc [2] 87 cb [2] 9b e4 }

  condition:
    any of them
}