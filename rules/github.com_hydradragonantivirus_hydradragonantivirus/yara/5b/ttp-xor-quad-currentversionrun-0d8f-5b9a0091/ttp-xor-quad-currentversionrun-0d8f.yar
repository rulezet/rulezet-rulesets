rule TTP_XOR_QUAD_CurrentVersionRun_0d8f {
  strings:
    $key_0d8f = { 5e e0 [2] 7a ee [2] 51 c2 [2] 7f e0 [2] 6b fb [2] 64 e1 [2] 7a fc [2] 78 fd [2] 63 fb [2] 7f fc [2] 63 d3 }

  condition:
    any of them
}