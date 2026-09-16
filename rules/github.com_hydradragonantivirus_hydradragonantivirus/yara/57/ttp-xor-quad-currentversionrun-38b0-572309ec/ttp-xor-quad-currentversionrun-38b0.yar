rule TTP_XOR_QUAD_CurrentVersionRun_38b0 {
  strings:
    $key_38b0 = { 6b df [2] 4f d1 [2] 64 fd [2] 4a df [2] 5e c4 [2] 51 de [2] 4f c3 [2] 4d c2 [2] 56 c4 [2] 4a c3 [2] 56 ec }

  condition:
    any of them
}