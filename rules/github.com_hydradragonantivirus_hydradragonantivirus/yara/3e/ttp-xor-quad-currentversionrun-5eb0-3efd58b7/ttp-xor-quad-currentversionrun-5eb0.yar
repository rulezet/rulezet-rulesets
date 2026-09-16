rule TTP_XOR_QUAD_CurrentVersionRun_5eb0 {
  strings:
    $key_5eb0 = { 0d df [2] 29 d1 [2] 02 fd [2] 2c df [2] 38 c4 [2] 37 de [2] 29 c3 [2] 2b c2 [2] 30 c4 [2] 2c c3 [2] 30 ec }

  condition:
    any of them
}