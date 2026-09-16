rule TTP_XOR_QUAD_CurrentVersionRun_5c8f {
  strings:
    $key_5c8f = { 0f e0 [2] 2b ee [2] 00 c2 [2] 2e e0 [2] 3a fb [2] 35 e1 [2] 2b fc [2] 29 fd [2] 32 fb [2] 2e fc [2] 32 d3 }

  condition:
    any of them
}