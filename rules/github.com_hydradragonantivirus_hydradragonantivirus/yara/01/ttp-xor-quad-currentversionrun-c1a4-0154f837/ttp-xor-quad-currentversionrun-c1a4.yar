rule TTP_XOR_QUAD_CurrentVersionRun_c1a4 {
  strings:
    $key_c1a4 = { 92 cb [2] b6 c5 [2] 9d e9 [2] b3 cb [2] a7 d0 [2] a8 ca [2] b6 d7 [2] b4 d6 [2] af d0 [2] b3 d7 [2] af f8 }

  condition:
    any of them
}