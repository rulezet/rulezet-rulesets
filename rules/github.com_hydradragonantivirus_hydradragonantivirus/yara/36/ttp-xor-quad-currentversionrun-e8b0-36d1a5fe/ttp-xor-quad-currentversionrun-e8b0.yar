rule TTP_XOR_QUAD_CurrentVersionRun_e8b0 {
  strings:
    $key_e8b0 = { bb df [2] 9f d1 [2] b4 fd [2] 9a df [2] 8e c4 [2] 81 de [2] 9f c3 [2] 9d c2 [2] 86 c4 [2] 9a c3 [2] 86 ec }

  condition:
    any of them
}