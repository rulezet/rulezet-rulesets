rule TTP_XOR_QUAD_CurrentVersionRun_608f {
  strings:
    $key_608f = { 33 e0 [2] 17 ee [2] 3c c2 [2] 12 e0 [2] 06 fb [2] 09 e1 [2] 17 fc [2] 15 fd [2] 0e fb [2] 12 fc [2] 0e d3 }

  condition:
    any of them
}