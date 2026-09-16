rule TTP_XOR_QUAD_CurrentVersionRun_778f {
  strings:
    $key_778f = { 24 e0 [2] 00 ee [2] 2b c2 [2] 05 e0 [2] 11 fb [2] 1e e1 [2] 00 fc [2] 02 fd [2] 19 fb [2] 05 fc [2] 19 d3 }

  condition:
    any of them
}