rule TTP_XOR_QUAD_CurrentVersionRun_c5a5 {
  strings:
    $key_c5a5 = { 96 ca [2] b2 c4 [2] 99 e8 [2] b7 ca [2] a3 d1 [2] ac cb [2] b2 d6 [2] b0 d7 [2] ab d1 [2] b7 d6 [2] ab f9 }

  condition:
    any of them
}