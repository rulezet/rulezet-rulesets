rule TTP_XOR_QUAD_CurrentVersionRun_968f {
  strings:
    $key_968f = { c5 e0 [2] e1 ee [2] ca c2 [2] e4 e0 [2] f0 fb [2] ff e1 [2] e1 fc [2] e3 fd [2] f8 fb [2] e4 fc [2] f8 d3 }

  condition:
    any of them
}