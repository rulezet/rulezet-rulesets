rule TTP_XOR_QUAD_CurrentVersionRun_8cb2 {
  strings:
    $key_8cb2 = { df dd [2] fb d3 [2] d0 ff [2] fe dd [2] ea c6 [2] e5 dc [2] fb c1 [2] f9 c0 [2] e2 c6 [2] fe c1 [2] e2 ee }

  condition:
    any of them
}