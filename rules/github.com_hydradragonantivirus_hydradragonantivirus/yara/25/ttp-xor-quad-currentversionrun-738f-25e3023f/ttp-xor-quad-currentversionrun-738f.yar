rule TTP_XOR_QUAD_CurrentVersionRun_738f {
  strings:
    $key_738f = { 20 e0 [2] 04 ee [2] 2f c2 [2] 01 e0 [2] 15 fb [2] 1a e1 [2] 04 fc [2] 06 fd [2] 1d fb [2] 01 fc [2] 1d d3 }

  condition:
    any of them
}