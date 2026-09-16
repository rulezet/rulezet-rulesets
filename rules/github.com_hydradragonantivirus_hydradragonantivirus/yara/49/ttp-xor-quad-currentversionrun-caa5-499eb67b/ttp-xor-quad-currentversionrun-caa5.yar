rule TTP_XOR_QUAD_CurrentVersionRun_caa5 {
  strings:
    $key_caa5 = { 99 ca [2] bd c4 [2] 96 e8 [2] b8 ca [2] ac d1 [2] a3 cb [2] bd d6 [2] bf d7 [2] a4 d1 [2] b8 d6 [2] a4 f9 }

  condition:
    any of them
}