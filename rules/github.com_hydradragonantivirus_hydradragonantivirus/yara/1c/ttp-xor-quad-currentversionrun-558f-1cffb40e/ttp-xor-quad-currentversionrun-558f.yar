rule TTP_XOR_QUAD_CurrentVersionRun_558f {
  strings:
    $key_558f = { 06 e0 [2] 22 ee [2] 09 c2 [2] 27 e0 [2] 33 fb [2] 3c e1 [2] 22 fc [2] 20 fd [2] 3b fb [2] 27 fc [2] 3b d3 }

  condition:
    any of them
}