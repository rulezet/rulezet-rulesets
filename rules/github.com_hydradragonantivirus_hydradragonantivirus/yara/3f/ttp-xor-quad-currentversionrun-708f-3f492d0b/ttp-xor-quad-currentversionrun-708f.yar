rule TTP_XOR_QUAD_CurrentVersionRun_708f {
  strings:
    $key_708f = { 23 e0 [2] 07 ee [2] 2c c2 [2] 02 e0 [2] 16 fb [2] 19 e1 [2] 07 fc [2] 05 fd [2] 1e fb [2] 02 fc [2] 1e d3 }

  condition:
    any of them
}