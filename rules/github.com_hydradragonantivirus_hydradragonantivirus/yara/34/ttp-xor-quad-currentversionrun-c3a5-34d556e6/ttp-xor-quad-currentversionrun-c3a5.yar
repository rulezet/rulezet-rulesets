rule TTP_XOR_QUAD_CurrentVersionRun_c3a5 {
  strings:
    $key_c3a5 = { 90 ca [2] b4 c4 [2] 9f e8 [2] b1 ca [2] a5 d1 [2] aa cb [2] b4 d6 [2] b6 d7 [2] ad d1 [2] b1 d6 [2] ad f9 }

  condition:
    any of them
}