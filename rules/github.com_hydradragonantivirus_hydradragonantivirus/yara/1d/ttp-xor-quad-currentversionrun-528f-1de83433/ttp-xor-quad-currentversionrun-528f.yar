rule TTP_XOR_QUAD_CurrentVersionRun_528f {
  strings:
    $key_528f = { 01 e0 [2] 25 ee [2] 0e c2 [2] 20 e0 [2] 34 fb [2] 3b e1 [2] 25 fc [2] 27 fd [2] 3c fb [2] 20 fc [2] 3c d3 }

  condition:
    any of them
}