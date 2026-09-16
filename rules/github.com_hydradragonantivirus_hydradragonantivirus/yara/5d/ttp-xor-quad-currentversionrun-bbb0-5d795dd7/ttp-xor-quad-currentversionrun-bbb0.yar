rule TTP_XOR_QUAD_CurrentVersionRun_bbb0 {
  strings:
    $key_bbb0 = { e8 df [2] cc d1 [2] e7 fd [2] c9 df [2] dd c4 [2] d2 de [2] cc c3 [2] ce c2 [2] d5 c4 [2] c9 c3 [2] d5 ec }

  condition:
    any of them
}