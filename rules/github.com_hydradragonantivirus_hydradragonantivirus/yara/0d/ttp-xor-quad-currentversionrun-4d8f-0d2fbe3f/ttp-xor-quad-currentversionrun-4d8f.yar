rule TTP_XOR_QUAD_CurrentVersionRun_4d8f {
  strings:
    $key_4d8f = { 1e e0 [2] 3a ee [2] 11 c2 [2] 3f e0 [2] 2b fb [2] 24 e1 [2] 3a fc [2] 38 fd [2] 23 fb [2] 3f fc [2] 23 d3 }

  condition:
    any of them
}