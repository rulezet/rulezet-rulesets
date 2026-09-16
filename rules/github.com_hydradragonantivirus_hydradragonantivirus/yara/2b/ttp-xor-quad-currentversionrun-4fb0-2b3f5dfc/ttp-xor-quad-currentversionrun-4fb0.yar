rule TTP_XOR_QUAD_CurrentVersionRun_4fb0 {
  strings:
    $key_4fb0 = { 1c df [2] 38 d1 [2] 13 fd [2] 3d df [2] 29 c4 [2] 26 de [2] 38 c3 [2] 3a c2 [2] 21 c4 [2] 3d c3 [2] 21 ec }

  condition:
    any of them
}