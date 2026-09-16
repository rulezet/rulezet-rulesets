rule TTP_XOR_QUAD_CurrentVersionRun_718f {
  strings:
    $key_718f = { 22 e0 [2] 06 ee [2] 2d c2 [2] 03 e0 [2] 17 fb [2] 18 e1 [2] 06 fc [2] 04 fd [2] 1f fb [2] 03 fc [2] 1f d3 }

  condition:
    any of them
}