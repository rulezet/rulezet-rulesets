rule TTP_XOR_QUAD_CurrentVersionRun_c7a5 {
  strings:
    $key_c7a5 = { 94 ca [2] b0 c4 [2] 9b e8 [2] b5 ca [2] a1 d1 [2] ae cb [2] b0 d6 [2] b2 d7 [2] a9 d1 [2] b5 d6 [2] a9 f9 }

  condition:
    any of them
}