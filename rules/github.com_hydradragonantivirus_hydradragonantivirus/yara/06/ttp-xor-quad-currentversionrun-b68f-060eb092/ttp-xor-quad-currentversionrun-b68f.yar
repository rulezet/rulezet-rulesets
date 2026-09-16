rule TTP_XOR_QUAD_CurrentVersionRun_b68f {
  strings:
    $key_b68f = { e5 e0 [2] c1 ee [2] ea c2 [2] c4 e0 [2] d0 fb [2] df e1 [2] c1 fc [2] c3 fd [2] d8 fb [2] c4 fc [2] d8 d3 }

  condition:
    any of them
}