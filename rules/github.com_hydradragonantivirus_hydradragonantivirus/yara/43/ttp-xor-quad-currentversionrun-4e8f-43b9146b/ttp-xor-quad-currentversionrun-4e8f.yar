rule TTP_XOR_QUAD_CurrentVersionRun_4e8f {
  strings:
    $key_4e8f = { 1d e0 [2] 39 ee [2] 12 c2 [2] 3c e0 [2] 28 fb [2] 27 e1 [2] 39 fc [2] 3b fd [2] 20 fb [2] 3c fc [2] 20 d3 }

  condition:
    any of them
}