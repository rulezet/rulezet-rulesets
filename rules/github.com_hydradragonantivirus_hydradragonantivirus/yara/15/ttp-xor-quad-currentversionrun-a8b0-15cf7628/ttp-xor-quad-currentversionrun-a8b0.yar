rule TTP_XOR_QUAD_CurrentVersionRun_a8b0 {
  strings:
    $key_a8b0 = { fb df [2] df d1 [2] f4 fd [2] da df [2] ce c4 [2] c1 de [2] df c3 [2] dd c2 [2] c6 c4 [2] da c3 [2] c6 ec }

  condition:
    any of them
}