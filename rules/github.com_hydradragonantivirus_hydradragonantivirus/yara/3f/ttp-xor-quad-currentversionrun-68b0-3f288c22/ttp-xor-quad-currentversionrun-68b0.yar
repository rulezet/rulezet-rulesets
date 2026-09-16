rule TTP_XOR_QUAD_CurrentVersionRun_68b0 {
  strings:
    $key_68b0 = { 3b df [2] 1f d1 [2] 34 fd [2] 1a df [2] 0e c4 [2] 01 de [2] 1f c3 [2] 1d c2 [2] 06 c4 [2] 1a c3 [2] 06 ec }

  condition:
    any of them
}