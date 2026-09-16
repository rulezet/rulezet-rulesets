rule TTP_XOR_QUAD_CurrentVersionRun_4f8f {
  strings:
    $key_4f8f = { 1c e0 [2] 38 ee [2] 13 c2 [2] 3d e0 [2] 29 fb [2] 26 e1 [2] 38 fc [2] 3a fd [2] 21 fb [2] 3d fc [2] 21 d3 }

  condition:
    any of them
}