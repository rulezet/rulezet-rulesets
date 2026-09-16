rule TTP_XOR_QUAD_CurrentVersionRun_d1a5 {
  strings:
    $key_d1a5 = { 82 ca [2] a6 c4 [2] 8d e8 [2] a3 ca [2] b7 d1 [2] b8 cb [2] a6 d6 [2] a4 d7 [2] bf d1 [2] a3 d6 [2] bf f9 }

  condition:
    any of them
}