rule TTP_XOR_QUAD_CurrentVersionRun_8cb5 {
  strings:
    $key_8cb5 = { df da [2] fb d4 [2] d0 f8 [2] fe da [2] ea c1 [2] e5 db [2] fb c6 [2] f9 c7 [2] e2 c1 [2] fe c6 [2] e2 e9 }

  condition:
    any of them
}