rule TTP_XOR_QUAD_CurrentVersionRun_8cd9 {
  strings:
    $key_8cd9 = { df b6 [2] fb b8 [2] d0 94 [2] fe b6 [2] ea ad [2] e5 b7 [2] fb aa [2] f9 ab [2] e2 ad [2] fe aa [2] e2 85 }

  condition:
    any of them
}