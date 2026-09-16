rule TTP_XOR_QUAD_CurrentVersionRun_87b0 {
  strings:
    $key_87b0 = { d4 df [2] f0 d1 [2] db fd [2] f5 df [2] e1 c4 [2] ee de [2] f0 c3 [2] f2 c2 [2] e9 c4 [2] f5 c3 [2] e9 ec }

  condition:
    any of them
}