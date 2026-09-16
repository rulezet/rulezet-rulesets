rule TTP_XOR_QUAD_CurrentVersionRun_2ba5 {
  strings:
    $key_2ba5 = { 78 ca [2] 5c c4 [2] 77 e8 [2] 59 ca [2] 4d d1 [2] 42 cb [2] 5c d6 [2] 5e d7 [2] 45 d1 [2] 59 d6 [2] 45 f9 }

  condition:
    any of them
}