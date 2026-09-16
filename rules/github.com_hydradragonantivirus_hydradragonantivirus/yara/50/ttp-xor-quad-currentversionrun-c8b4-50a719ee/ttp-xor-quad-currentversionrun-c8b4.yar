rule TTP_XOR_QUAD_CurrentVersionRun_c8b4 {
  strings:
    $key_c8b4 = { 9b db [2] bf d5 [2] 94 f9 [2] ba db [2] ae c0 [2] a1 da [2] bf c7 [2] bd c6 [2] a6 c0 [2] ba c7 [2] a6 e8 }

  condition:
    any of them
}