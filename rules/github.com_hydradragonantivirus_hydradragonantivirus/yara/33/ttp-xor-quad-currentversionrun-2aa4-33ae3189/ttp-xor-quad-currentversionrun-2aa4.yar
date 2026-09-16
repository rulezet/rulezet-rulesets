rule TTP_XOR_QUAD_CurrentVersionRun_2aa4 {
  strings:
    $key_2aa4 = { 79 cb [2] 5d c5 [2] 76 e9 [2] 58 cb [2] 4c d0 [2] 43 ca [2] 5d d7 [2] 5f d6 [2] 44 d0 [2] 58 d7 [2] 44 f8 }

  condition:
    any of them
}