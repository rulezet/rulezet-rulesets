rule TTP_XOR_QUAD_CurrentVersionRun_c0b8 {
  strings:
    $key_c0b8 = { 93 d7 [2] b7 d9 [2] 9c f5 [2] b2 d7 [2] a6 cc [2] a9 d6 [2] b7 cb [2] b5 ca [2] ae cc [2] b2 cb [2] ae e4 }

  condition:
    any of them
}