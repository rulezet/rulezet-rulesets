rule TTP_XOR_QUAD_CurrentVersionRun_9fb0 {
  strings:
    $key_9fb0 = { cc df [2] e8 d1 [2] c3 fd [2] ed df [2] f9 c4 [2] f6 de [2] e8 c3 [2] ea c2 [2] f1 c4 [2] ed c3 [2] f1 ec }

  condition:
    any of them
}