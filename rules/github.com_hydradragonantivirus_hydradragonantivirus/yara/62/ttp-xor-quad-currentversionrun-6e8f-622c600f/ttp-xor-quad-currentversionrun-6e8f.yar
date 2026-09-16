rule TTP_XOR_QUAD_CurrentVersionRun_6e8f {
  strings:
    $key_6e8f = { 3d e0 [2] 19 ee [2] 32 c2 [2] 1c e0 [2] 08 fb [2] 07 e1 [2] 19 fc [2] 1b fd [2] 00 fb [2] 1c fc [2] 00 d3 }

  condition:
    any of them
}