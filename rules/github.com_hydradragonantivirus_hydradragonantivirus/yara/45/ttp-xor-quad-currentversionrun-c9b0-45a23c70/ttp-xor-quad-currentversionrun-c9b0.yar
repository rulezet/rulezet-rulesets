rule TTP_XOR_QUAD_CurrentVersionRun_c9b0 {
  strings:
    $key_c9b0 = { 9a df [2] be d1 [2] 95 fd [2] bb df [2] af c4 [2] a0 de [2] be c3 [2] bc c2 [2] a7 c4 [2] bb c3 [2] a7 ec }

  condition:
    any of them
}