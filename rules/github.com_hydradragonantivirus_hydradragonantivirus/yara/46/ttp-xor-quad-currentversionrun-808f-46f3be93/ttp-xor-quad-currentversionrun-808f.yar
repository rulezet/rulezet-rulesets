rule TTP_XOR_QUAD_CurrentVersionRun_808f {
  strings:
    $key_808f = { d3 e0 [2] f7 ee [2] dc c2 [2] f2 e0 [2] e6 fb [2] e9 e1 [2] f7 fc [2] f5 fd [2] ee fb [2] f2 fc [2] ee d3 }

  condition:
    any of them
}