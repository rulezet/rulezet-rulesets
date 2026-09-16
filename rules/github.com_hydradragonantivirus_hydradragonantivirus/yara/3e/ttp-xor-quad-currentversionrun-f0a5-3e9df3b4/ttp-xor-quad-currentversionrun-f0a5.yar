rule TTP_XOR_QUAD_CurrentVersionRun_f0a5 {
  strings:
    $key_f0a5 = { a3 ca [2] 87 c4 [2] ac e8 [2] 82 ca [2] 96 d1 [2] 99 cb [2] 87 d6 [2] 85 d7 [2] 9e d1 [2] 82 d6 [2] 9e f9 }

  condition:
    any of them
}