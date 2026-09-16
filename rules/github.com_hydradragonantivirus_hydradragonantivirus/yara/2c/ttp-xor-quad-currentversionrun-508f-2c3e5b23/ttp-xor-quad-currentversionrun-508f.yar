rule TTP_XOR_QUAD_CurrentVersionRun_508f {
  strings:
    $key_508f = { 03 e0 [2] 27 ee [2] 0c c2 [2] 22 e0 [2] 36 fb [2] 39 e1 [2] 27 fc [2] 25 fd [2] 3e fb [2] 22 fc [2] 3e d3 }

  condition:
    any of them
}