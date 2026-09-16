rule TTP_XOR_QUAD_CurrentVersionRun_658f {
  strings:
    $key_658f = { 36 e0 [2] 12 ee [2] 39 c2 [2] 17 e0 [2] 03 fb [2] 0c e1 [2] 12 fc [2] 10 fd [2] 0b fb [2] 17 fc [2] 0b d3 }

  condition:
    any of them
}