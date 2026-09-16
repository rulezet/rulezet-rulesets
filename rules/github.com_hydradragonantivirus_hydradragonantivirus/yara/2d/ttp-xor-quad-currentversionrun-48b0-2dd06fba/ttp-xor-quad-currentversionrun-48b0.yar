rule TTP_XOR_QUAD_CurrentVersionRun_48b0 {
  strings:
    $key_48b0 = { 1b df [2] 3f d1 [2] 14 fd [2] 3a df [2] 2e c4 [2] 21 de [2] 3f c3 [2] 3d c2 [2] 26 c4 [2] 3a c3 [2] 26 ec }

  condition:
    any of them
}