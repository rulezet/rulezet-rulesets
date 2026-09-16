rule TTP_XOR_QUAD_CurrentVersionRun_c8b0 {
  strings:
    $key_c8b0 = { 9b df [2] bf d1 [2] 94 fd [2] ba df [2] ae c4 [2] a1 de [2] bf c3 [2] bd c2 [2] a6 c4 [2] ba c3 [2] a6 ec }

  condition:
    any of them
}