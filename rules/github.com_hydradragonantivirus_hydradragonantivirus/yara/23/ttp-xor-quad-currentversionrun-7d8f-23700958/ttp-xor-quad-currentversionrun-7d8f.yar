rule TTP_XOR_QUAD_CurrentVersionRun_7d8f {
  strings:
    $key_7d8f = { 2e e0 [2] 0a ee [2] 21 c2 [2] 0f e0 [2] 1b fb [2] 14 e1 [2] 0a fc [2] 08 fd [2] 13 fb [2] 0f fc [2] 13 d3 }

  condition:
    any of them
}