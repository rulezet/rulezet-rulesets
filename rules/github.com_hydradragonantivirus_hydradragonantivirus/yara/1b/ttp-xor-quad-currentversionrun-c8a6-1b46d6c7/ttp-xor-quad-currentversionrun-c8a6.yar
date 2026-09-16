rule TTP_XOR_QUAD_CurrentVersionRun_c8a6 {
  strings:
    $key_c8a6 = { 9b c9 [2] bf c7 [2] 94 eb [2] ba c9 [2] ae d2 [2] a1 c8 [2] bf d5 [2] bd d4 [2] a6 d2 [2] ba d5 [2] a6 fa }

  condition:
    any of them
}