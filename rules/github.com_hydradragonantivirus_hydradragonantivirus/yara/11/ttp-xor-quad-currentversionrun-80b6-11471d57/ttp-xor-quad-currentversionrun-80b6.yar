rule TTP_XOR_QUAD_CurrentVersionRun_80b6 {
  strings:
    $key_80b6 = { d3 d9 [2] f7 d7 [2] dc fb [2] f2 d9 [2] e6 c2 [2] e9 d8 [2] f7 c5 [2] f5 c4 [2] ee c2 [2] f2 c5 [2] ee ea }

  condition:
    any of them
}