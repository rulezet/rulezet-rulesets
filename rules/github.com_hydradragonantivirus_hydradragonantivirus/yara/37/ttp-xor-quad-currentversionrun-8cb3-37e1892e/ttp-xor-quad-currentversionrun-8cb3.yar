rule TTP_XOR_QUAD_CurrentVersionRun_8cb3 {
  strings:
    $key_8cb3 = { df dc [2] fb d2 [2] d0 fe [2] fe dc [2] ea c7 [2] e5 dd [2] fb c0 [2] f9 c1 [2] e2 c7 [2] fe c0 [2] e2 ef }

  condition:
    any of them
}