rule TTP_XOR_QUAD_CurrentVersionRun_b08f {
  strings:
    $key_b08f = { e3 e0 [2] c7 ee [2] ec c2 [2] c2 e0 [2] d6 fb [2] d9 e1 [2] c7 fc [2] c5 fd [2] de fb [2] c2 fc [2] de d3 }

  condition:
    any of them
}