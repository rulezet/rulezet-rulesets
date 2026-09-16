rule TTP_XOR_QUAD_CurrentVersionRun_878f {
  strings:
    $key_878f = { d4 e0 [2] f0 ee [2] db c2 [2] f5 e0 [2] e1 fb [2] ee e1 [2] f0 fc [2] f2 fd [2] e9 fb [2] f5 fc [2] e9 d3 }

  condition:
    any of them
}