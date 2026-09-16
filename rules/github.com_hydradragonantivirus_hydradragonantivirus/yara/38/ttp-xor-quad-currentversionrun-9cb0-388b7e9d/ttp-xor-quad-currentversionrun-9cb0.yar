rule TTP_XOR_QUAD_CurrentVersionRun_9cb0 {
  strings:
    $key_9cb0 = { cf df [2] eb d1 [2] c0 fd [2] ee df [2] fa c4 [2] f5 de [2] eb c3 [2] e9 c2 [2] f2 c4 [2] ee c3 [2] f2 ec }

  condition:
    any of them
}