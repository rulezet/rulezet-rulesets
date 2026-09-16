rule TTP_XOR_QUAD_CurrentVersionRun_2d8f {
  strings:
    $key_2d8f = { 7e e0 [2] 5a ee [2] 71 c2 [2] 5f e0 [2] 4b fb [2] 44 e1 [2] 5a fc [2] 58 fd [2] 43 fb [2] 5f fc [2] 43 d3 }

  condition:
    any of them
}