rule TTP_XOR_QUAD_CurrentVersionRun_80b0 {
  strings:
    $key_80b0 = { d3 df [2] f7 d1 [2] dc fd [2] f2 df [2] e6 c4 [2] e9 de [2] f7 c3 [2] f5 c2 [2] ee c4 [2] f2 c3 [2] ee ec }

  condition:
    any of them
}