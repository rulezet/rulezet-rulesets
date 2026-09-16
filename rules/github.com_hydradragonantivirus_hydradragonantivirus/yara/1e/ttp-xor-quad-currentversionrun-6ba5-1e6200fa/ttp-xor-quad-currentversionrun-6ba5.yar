rule TTP_XOR_QUAD_CurrentVersionRun_6ba5 {
  strings:
    $key_6ba5 = { 38 ca [2] 1c c4 [2] 37 e8 [2] 19 ca [2] 0d d1 [2] 02 cb [2] 1c d6 [2] 1e d7 [2] 05 d1 [2] 19 d6 [2] 05 f9 }

  condition:
    any of them
}