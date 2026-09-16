rule TTP_XOR_QUAD_CurrentVersionRun_8ca0 {
  strings:
    $key_8ca0 = { df cf [2] fb c1 [2] d0 ed [2] fe cf [2] ea d4 [2] e5 ce [2] fb d3 [2] f9 d2 [2] e2 d4 [2] fe d3 [2] e2 fc }

  condition:
    any of them
}