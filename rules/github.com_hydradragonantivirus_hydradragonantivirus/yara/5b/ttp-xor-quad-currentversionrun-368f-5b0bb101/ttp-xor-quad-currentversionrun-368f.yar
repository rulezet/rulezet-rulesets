rule TTP_XOR_QUAD_CurrentVersionRun_368f {
  strings:
    $key_368f = { 65 e0 [2] 41 ee [2] 6a c2 [2] 44 e0 [2] 50 fb [2] 5f e1 [2] 41 fc [2] 43 fd [2] 58 fb [2] 44 fc [2] 58 d3 }

  condition:
    any of them
}