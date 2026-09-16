rule TTP_XOR_QUAD_CurrentVersionRun_fc8f {
  strings:
    $key_fc8f = { af e0 [2] 8b ee [2] a0 c2 [2] 8e e0 [2] 9a fb [2] 95 e1 [2] 8b fc [2] 89 fd [2] 92 fb [2] 8e fc [2] 92 d3 }

  condition:
    any of them
}