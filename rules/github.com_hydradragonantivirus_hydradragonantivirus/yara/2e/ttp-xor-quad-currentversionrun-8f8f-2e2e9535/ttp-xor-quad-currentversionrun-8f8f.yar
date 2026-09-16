rule TTP_XOR_QUAD_CurrentVersionRun_8f8f {
  strings:
    $key_8f8f = { dc e0 [2] f8 ee [2] d3 c2 [2] fd e0 [2] e9 fb [2] e6 e1 [2] f8 fc [2] fa fd [2] e1 fb [2] fd fc [2] e1 d3 }

  condition:
    any of them
}