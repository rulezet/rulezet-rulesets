rule TTP_XOR_QUAD_CurrentVersionRun_1fb0 {
  strings:
    $key_1fb0 = { 4c df [2] 68 d1 [2] 43 fd [2] 6d df [2] 79 c4 [2] 76 de [2] 68 c3 [2] 6a c2 [2] 71 c4 [2] 6d c3 [2] 71 ec }

  condition:
    any of them
}