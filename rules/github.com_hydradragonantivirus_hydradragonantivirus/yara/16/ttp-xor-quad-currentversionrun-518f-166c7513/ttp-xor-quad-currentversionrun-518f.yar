rule TTP_XOR_QUAD_CurrentVersionRun_518f {
  strings:
    $key_518f = { 02 e0 [2] 26 ee [2] 0d c2 [2] 23 e0 [2] 37 fb [2] 38 e1 [2] 26 fc [2] 24 fd [2] 3f fb [2] 23 fc [2] 3f d3 }

  condition:
    any of them
}