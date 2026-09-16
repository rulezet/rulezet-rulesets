rule TTP_XOR_QUAD_CurrentVersionRun_568f {
  strings:
    $key_568f = { 05 e0 [2] 21 ee [2] 0a c2 [2] 24 e0 [2] 30 fb [2] 3f e1 [2] 21 fc [2] 23 fd [2] 38 fb [2] 24 fc [2] 38 d3 }

  condition:
    any of them
}