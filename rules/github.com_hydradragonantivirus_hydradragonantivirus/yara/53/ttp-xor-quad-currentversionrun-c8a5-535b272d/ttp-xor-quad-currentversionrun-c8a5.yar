rule TTP_XOR_QUAD_CurrentVersionRun_c8a5 {
  strings:
    $key_c8a5 = { 9b ca [2] bf c4 [2] 94 e8 [2] ba ca [2] ae d1 [2] a1 cb [2] bf d6 [2] bd d7 [2] a6 d1 [2] ba d6 [2] a6 f9 }

  condition:
    any of them
}