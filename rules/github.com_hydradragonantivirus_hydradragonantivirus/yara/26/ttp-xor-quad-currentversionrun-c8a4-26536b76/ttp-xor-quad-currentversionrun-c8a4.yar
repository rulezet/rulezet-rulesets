rule TTP_XOR_QUAD_CurrentVersionRun_c8a4 {
  strings:
    $key_c8a4 = { 9b cb [2] bf c5 [2] 94 e9 [2] ba cb [2] ae d0 [2] a1 ca [2] bf d7 [2] bd d6 [2] a6 d0 [2] ba d7 [2] a6 f8 }

  condition:
    any of them
}