rule TTP_XOR_QUAD_CurrentVersionRun_8084 {
  strings:
    $key_8084 = { d3 eb [2] f7 e5 [2] dc c9 [2] f2 eb [2] e6 f0 [2] e9 ea [2] f7 f7 [2] f5 f6 [2] ee f0 [2] f2 f7 [2] ee d8 }

  condition:
    any of them
}