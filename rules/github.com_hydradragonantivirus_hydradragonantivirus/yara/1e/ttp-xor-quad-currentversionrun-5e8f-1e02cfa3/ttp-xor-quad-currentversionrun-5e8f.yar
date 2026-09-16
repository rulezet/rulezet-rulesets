rule TTP_XOR_QUAD_CurrentVersionRun_5e8f {
  strings:
    $key_5e8f = { 0d e0 [2] 29 ee [2] 02 c2 [2] 2c e0 [2] 38 fb [2] 37 e1 [2] 29 fc [2] 2b fd [2] 30 fb [2] 2c fc [2] 30 d3 }

  condition:
    any of them
}