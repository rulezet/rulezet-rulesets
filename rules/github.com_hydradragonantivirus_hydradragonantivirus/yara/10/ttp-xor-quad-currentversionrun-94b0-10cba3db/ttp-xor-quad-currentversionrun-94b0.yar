rule TTP_XOR_QUAD_CurrentVersionRun_94b0 {
  strings:
    $key_94b0 = { c7 df [2] e3 d1 [2] c8 fd [2] e6 df [2] f2 c4 [2] fd de [2] e3 c3 [2] e1 c2 [2] fa c4 [2] e6 c3 [2] fa ec }

  condition:
    any of them
}