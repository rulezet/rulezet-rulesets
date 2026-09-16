rule TTP_XOR_QUAD_CurrentVersionRun_918f {
  strings:
    $key_918f = { c2 e0 [2] e6 ee [2] cd c2 [2] e3 e0 [2] f7 fb [2] f8 e1 [2] e6 fc [2] e4 fd [2] ff fb [2] e3 fc [2] ff d3 }

  condition:
    any of them
}