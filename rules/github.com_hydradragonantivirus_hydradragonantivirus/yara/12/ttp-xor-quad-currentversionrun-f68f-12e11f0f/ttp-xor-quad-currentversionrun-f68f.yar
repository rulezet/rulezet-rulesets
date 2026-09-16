rule TTP_XOR_QUAD_CurrentVersionRun_f68f {
  strings:
    $key_f68f = { a5 e0 [2] 81 ee [2] aa c2 [2] 84 e0 [2] 90 fb [2] 9f e1 [2] 81 fc [2] 83 fd [2] 98 fb [2] 84 fc [2] 98 d3 }

  condition:
    any of them
}