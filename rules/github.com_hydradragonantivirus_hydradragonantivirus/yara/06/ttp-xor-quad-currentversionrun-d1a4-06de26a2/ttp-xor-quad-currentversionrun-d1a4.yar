rule TTP_XOR_QUAD_CurrentVersionRun_d1a4 {
  strings:
    $key_d1a4 = { 82 cb [2] a6 c5 [2] 8d e9 [2] a3 cb [2] b7 d0 [2] b8 ca [2] a6 d7 [2] a4 d6 [2] bf d0 [2] a3 d7 [2] bf f8 }

  condition:
    any of them
}