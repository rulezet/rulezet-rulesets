rule TTP_XOR_QUAD_CurrentVersionRun_8cbb {
  strings:
    $key_8cbb = { df d4 [2] fb da [2] d0 f6 [2] fe d4 [2] ea cf [2] e5 d5 [2] fb c8 [2] f9 c9 [2] e2 cf [2] fe c8 [2] e2 e7 }

  condition:
    any of them
}