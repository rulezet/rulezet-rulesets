rule TTP_XOR_QUAD_CurrentVersionRun_8cd1 {
  strings:
    $key_8cd1 = { df be [2] fb b0 [2] d0 9c [2] fe be [2] ea a5 [2] e5 bf [2] fb a2 [2] f9 a3 [2] e2 a5 [2] fe a2 [2] e2 8d }

  condition:
    any of them
}