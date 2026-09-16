rule TTP_XOR_QUAD_CurrentVersionRun_97b0 {
  strings:
    $key_97b0 = { c4 df [2] e0 d1 [2] cb fd [2] e5 df [2] f1 c4 [2] fe de [2] e0 c3 [2] e2 c2 [2] f9 c4 [2] e5 c3 [2] f9 ec }

  condition:
    any of them
}