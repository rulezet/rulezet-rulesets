rule TTP_XOR_QUAD_CurrentVersionRun_8081 {
  strings:
    $key_8081 = { d3 ee [2] f7 e0 [2] dc cc [2] f2 ee [2] e6 f5 [2] e9 ef [2] f7 f2 [2] f5 f3 [2] ee f5 [2] f2 f2 [2] ee dd }

  condition:
    any of them
}