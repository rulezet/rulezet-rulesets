rule TTP_XOR_QUAD_CurrentVersionRun_c8a7 {
  strings:
    $key_c8a7 = { 9b c8 [2] bf c6 [2] 94 ea [2] ba c8 [2] ae d3 [2] a1 c9 [2] bf d4 [2] bd d5 [2] a6 d3 [2] ba d4 [2] a6 fb }

  condition:
    any of them
}