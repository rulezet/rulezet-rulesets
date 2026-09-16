rule TTP_XOR_QUAD_CurrentVersionRun_f5bf {
  strings:
    $key_f5bf = { a6 d0 [2] 82 de [2] a9 f2 [2] 87 d0 [2] 93 cb [2] 9c d1 [2] 82 cc [2] 80 cd [2] 9b cb [2] 87 cc [2] 9b e3 }

  condition:
    any of them
}