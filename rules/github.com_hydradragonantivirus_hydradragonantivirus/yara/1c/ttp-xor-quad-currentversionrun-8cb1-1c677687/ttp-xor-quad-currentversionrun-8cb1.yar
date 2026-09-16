rule TTP_XOR_QUAD_CurrentVersionRun_8cb1 {
  strings:
    $key_8cb1 = { df de [2] fb d0 [2] d0 fc [2] fe de [2] ea c5 [2] e5 df [2] fb c2 [2] f9 c3 [2] e2 c5 [2] fe c2 [2] e2 ed }

  condition:
    any of them
}