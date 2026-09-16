rule TTP_XOR_QUAD_CurrentVersionRun_78b0 {
  strings:
    $key_78b0 = { 2b df [2] 0f d1 [2] 24 fd [2] 0a df [2] 1e c4 [2] 11 de [2] 0f c3 [2] 0d c2 [2] 16 c4 [2] 0a c3 [2] 16 ec }

  condition:
    any of them
}