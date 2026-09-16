rule TTP_XOR_QUAD_CurrentVersionRun_f5a4 {
  strings:
    $key_f5a4 = { a6 cb [2] 82 c5 [2] a9 e9 [2] 87 cb [2] 93 d0 [2] 9c ca [2] 82 d7 [2] 80 d6 [2] 9b d0 [2] 87 d7 [2] 9b f8 }

  condition:
    any of them
}