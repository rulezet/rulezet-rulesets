rule TTP_XOR_QUAD_CurrentVersionRun_a68f {
  strings:
    $key_a68f = { f5 e0 [2] d1 ee [2] fa c2 [2] d4 e0 [2] c0 fb [2] cf e1 [2] d1 fc [2] d3 fd [2] c8 fb [2] d4 fc [2] c8 d3 }

  condition:
    any of them
}