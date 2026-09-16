rule TTP_XOR_QUAD_CurrentVersionRun_31a4 {
  strings:
    $key_31a4 = { 62 cb [2] 46 c5 [2] 6d e9 [2] 43 cb [2] 57 d0 [2] 58 ca [2] 46 d7 [2] 44 d6 [2] 5f d0 [2] 43 d7 [2] 5f f8 }

  condition:
    any of them
}