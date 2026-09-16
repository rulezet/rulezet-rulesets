rule TTP_XOR_QUAD_CurrentVersionRun_84b0 {
  strings:
    $key_84b0 = { d7 df [2] f3 d1 [2] d8 fd [2] f6 df [2] e2 c4 [2] ed de [2] f3 c3 [2] f1 c2 [2] ea c4 [2] f6 c3 [2] ea ec }

  condition:
    any of them
}