rule TTP_XOR_QUAD_CurrentVersionRun_8cd5 {
  strings:
    $key_8cd5 = { df ba [2] fb b4 [2] d0 98 [2] fe ba [2] ea a1 [2] e5 bb [2] fb a6 [2] f9 a7 [2] e2 a1 [2] fe a6 [2] e2 89 }

  condition:
    any of them
}