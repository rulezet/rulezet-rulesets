rule TTP_XOR_QUAD_CurrentVersionRun_6d8f {
  strings:
    $key_6d8f = { 3e e0 [2] 1a ee [2] 31 c2 [2] 1f e0 [2] 0b fb [2] 04 e1 [2] 1a fc [2] 18 fd [2] 03 fb [2] 1f fc [2] 03 d3 }

  condition:
    any of them
}