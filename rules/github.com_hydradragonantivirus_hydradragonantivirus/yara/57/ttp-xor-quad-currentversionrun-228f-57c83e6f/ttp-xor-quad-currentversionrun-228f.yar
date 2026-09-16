rule TTP_XOR_QUAD_CurrentVersionRun_228f {
  strings:
    $key_228f = { 71 e0 [2] 55 ee [2] 7e c2 [2] 50 e0 [2] 44 fb [2] 4b e1 [2] 55 fc [2] 57 fd [2] 4c fb [2] 50 fc [2] 4c d3 }

  condition:
    any of them
}