rule TTP_XOR_QUAD_CurrentVersionRun_808e {
  strings:
    $key_808e = { d3 e1 [2] f7 ef [2] dc c3 [2] f2 e1 [2] e6 fa [2] e9 e0 [2] f7 fd [2] f5 fc [2] ee fa [2] f2 fd [2] ee d2 }

  condition:
    any of them
}