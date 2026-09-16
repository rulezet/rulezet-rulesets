rule TTP_XOR_QUAD_CurrentVersionRun_938f {
  strings:
    $key_938f = { c0 e0 [2] e4 ee [2] cf c2 [2] e1 e0 [2] f5 fb [2] fa e1 [2] e4 fc [2] e6 fd [2] fd fb [2] e1 fc [2] fd d3 }

  condition:
    any of them
}