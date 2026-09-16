rule TTP_XOR_QUAD_CurrentVersionRun_4a8f {
  strings:
    $key_4a8f = { 19 e0 [2] 3d ee [2] 16 c2 [2] 38 e0 [2] 2c fb [2] 23 e1 [2] 3d fc [2] 3f fd [2] 24 fb [2] 38 fc [2] 24 d3 }

  condition:
    any of them
}