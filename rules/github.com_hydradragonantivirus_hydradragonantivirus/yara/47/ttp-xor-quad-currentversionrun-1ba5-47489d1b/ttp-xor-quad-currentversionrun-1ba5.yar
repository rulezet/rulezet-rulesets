rule TTP_XOR_QUAD_CurrentVersionRun_1ba5 {
  strings:
    $key_1ba5 = { 48 ca [2] 6c c4 [2] 47 e8 [2] 69 ca [2] 7d d1 [2] 72 cb [2] 6c d6 [2] 6e d7 [2] 75 d1 [2] 69 d6 [2] 75 f9 }

  condition:
    any of them
}