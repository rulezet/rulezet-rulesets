rule TTP_XOR_QUAD_CurrentVersionRun_258f {
  strings:
    $key_258f = { 76 e0 [2] 52 ee [2] 79 c2 [2] 57 e0 [2] 43 fb [2] 4c e1 [2] 52 fc [2] 50 fd [2] 4b fb [2] 57 fc [2] 4b d3 }

  condition:
    any of them
}