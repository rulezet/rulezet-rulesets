rule TTP_XOR_QUAD_CurrentVersionRun_f5aa {
  strings:
    $key_f5aa = { a6 c5 [2] 82 cb [2] a9 e7 [2] 87 c5 [2] 93 de [2] 9c c4 [2] 82 d9 [2] 80 d8 [2] 9b de [2] 87 d9 [2] 9b f6 }

  condition:
    any of them
}