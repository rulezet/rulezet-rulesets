rule TTP_XOR_QUAD_CurrentVersionRun_c1a5 {
  strings:
    $key_c1a5 = { 92 ca [2] b6 c4 [2] 9d e8 [2] b3 ca [2] a7 d1 [2] a8 cb [2] b6 d6 [2] b4 d7 [2] af d1 [2] b3 d6 [2] af f9 }

  condition:
    any of them
}