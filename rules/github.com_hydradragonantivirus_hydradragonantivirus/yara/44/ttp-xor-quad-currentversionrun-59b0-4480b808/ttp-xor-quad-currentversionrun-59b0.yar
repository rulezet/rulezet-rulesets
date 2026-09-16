rule TTP_XOR_QUAD_CurrentVersionRun_59b0 {
  strings:
    $key_59b0 = { 0a df [2] 2e d1 [2] 05 fd [2] 2b df [2] 3f c4 [2] 30 de [2] 2e c3 [2] 2c c2 [2] 37 c4 [2] 2b c3 [2] 37 ec }

  condition:
    any of them
}