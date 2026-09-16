rule TTP_XOR_QUAD_CurrentVersionRun_96b0 {
  strings:
    $key_96b0 = { c5 df [2] e1 d1 [2] ca fd [2] e4 df [2] f0 c4 [2] ff de [2] e1 c3 [2] e3 c2 [2] f8 c4 [2] e4 c3 [2] f8 ec }

  condition:
    any of them
}