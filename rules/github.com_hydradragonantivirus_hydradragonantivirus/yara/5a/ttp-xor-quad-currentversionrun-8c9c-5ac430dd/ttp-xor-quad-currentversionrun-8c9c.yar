rule TTP_XOR_QUAD_CurrentVersionRun_8c9c {
  strings:
    $key_8c9c = { df f3 [2] fb fd [2] d0 d1 [2] fe f3 [2] ea e8 [2] e5 f2 [2] fb ef [2] f9 ee [2] e2 e8 [2] fe ef [2] e2 c0 }

  condition:
    any of them
}