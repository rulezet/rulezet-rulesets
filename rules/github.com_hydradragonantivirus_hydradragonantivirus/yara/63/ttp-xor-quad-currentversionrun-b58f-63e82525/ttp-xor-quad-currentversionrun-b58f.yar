rule TTP_XOR_QUAD_CurrentVersionRun_b58f {
  strings:
    $key_b58f = { e6 e0 [2] c2 ee [2] e9 c2 [2] c7 e0 [2] d3 fb [2] dc e1 [2] c2 fc [2] c0 fd [2] db fb [2] c7 fc [2] db d3 }

  condition:
    any of them
}