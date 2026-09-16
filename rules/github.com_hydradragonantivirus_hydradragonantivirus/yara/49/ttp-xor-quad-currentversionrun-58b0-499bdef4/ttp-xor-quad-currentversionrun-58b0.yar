rule TTP_XOR_QUAD_CurrentVersionRun_58b0 {
  strings:
    $key_58b0 = { 0b df [2] 2f d1 [2] 04 fd [2] 2a df [2] 3e c4 [2] 31 de [2] 2f c3 [2] 2d c2 [2] 36 c4 [2] 2a c3 [2] 36 ec }

  condition:
    any of them
}