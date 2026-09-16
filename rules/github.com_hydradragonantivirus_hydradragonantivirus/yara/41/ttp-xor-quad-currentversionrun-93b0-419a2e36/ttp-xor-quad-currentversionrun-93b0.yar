rule TTP_XOR_QUAD_CurrentVersionRun_93b0 {
  strings:
    $key_93b0 = { c0 df [2] e4 d1 [2] cf fd [2] e1 df [2] f5 c4 [2] fa de [2] e4 c3 [2] e6 c2 [2] fd c4 [2] e1 c3 [2] fd ec }

  condition:
    any of them
}