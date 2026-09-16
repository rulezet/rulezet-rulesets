rule TTP_XOR_QUAD_CurrentVersionRun_c5b8 {
  strings:
    $key_c5b8 = { 96 d7 [2] b2 d9 [2] 99 f5 [2] b7 d7 [2] a3 cc [2] ac d6 [2] b2 cb [2] b0 ca [2] ab cc [2] b7 cb [2] ab e4 }

  condition:
    any of them
}