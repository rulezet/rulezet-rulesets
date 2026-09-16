rule TTP_XOR_QUAD_CurrentVersionRun_f7b8 {
  strings:
    $key_f7b8 = { a4 d7 [2] 80 d9 [2] ab f5 [2] 85 d7 [2] 91 cc [2] 9e d6 [2] 80 cb [2] 82 ca [2] 99 cc [2] 85 cb [2] 99 e4 }

  condition:
    any of them
}