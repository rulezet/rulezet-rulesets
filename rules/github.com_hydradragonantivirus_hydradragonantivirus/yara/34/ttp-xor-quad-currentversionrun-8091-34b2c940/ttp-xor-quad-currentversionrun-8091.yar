rule TTP_XOR_QUAD_CurrentVersionRun_8091 {
  strings:
    $key_8091 = { d3 fe [2] f7 f0 [2] dc dc [2] f2 fe [2] e6 e5 [2] e9 ff [2] f7 e2 [2] f5 e3 [2] ee e5 [2] f2 e2 [2] ee cd }

  condition:
    any of them
}