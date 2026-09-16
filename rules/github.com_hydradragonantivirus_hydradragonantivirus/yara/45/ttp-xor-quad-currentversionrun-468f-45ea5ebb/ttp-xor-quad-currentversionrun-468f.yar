rule TTP_XOR_QUAD_CurrentVersionRun_468f {
  strings:
    $key_468f = { 15 e0 [2] 31 ee [2] 1a c2 [2] 34 e0 [2] 20 fb [2] 2f e1 [2] 31 fc [2] 33 fd [2] 28 fb [2] 34 fc [2] 28 d3 }

  condition:
    any of them
}