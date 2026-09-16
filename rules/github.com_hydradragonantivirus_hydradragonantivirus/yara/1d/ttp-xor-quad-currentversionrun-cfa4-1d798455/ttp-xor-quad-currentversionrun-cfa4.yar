rule TTP_XOR_QUAD_CurrentVersionRun_cfa4 {
  strings:
    $key_cfa4 = { 9c cb [2] b8 c5 [2] 93 e9 [2] bd cb [2] a9 d0 [2] a6 ca [2] b8 d7 [2] ba d6 [2] a1 d0 [2] bd d7 [2] a1 f8 }

  condition:
    any of them
}