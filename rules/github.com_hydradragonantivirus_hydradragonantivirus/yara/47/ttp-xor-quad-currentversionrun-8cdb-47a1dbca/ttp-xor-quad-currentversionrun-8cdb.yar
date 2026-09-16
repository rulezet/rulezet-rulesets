rule TTP_XOR_QUAD_CurrentVersionRun_8cdb {
  strings:
    $key_8cdb = { df b4 [2] fb ba [2] d0 96 [2] fe b4 [2] ea af [2] e5 b5 [2] fb a8 [2] f9 a9 [2] e2 af [2] fe a8 [2] e2 87 }

  condition:
    any of them
}