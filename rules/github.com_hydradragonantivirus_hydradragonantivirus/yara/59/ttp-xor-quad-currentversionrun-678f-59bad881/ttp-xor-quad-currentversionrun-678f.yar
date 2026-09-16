rule TTP_XOR_QUAD_CurrentVersionRun_678f {
  strings:
    $key_678f = { 34 e0 [2] 10 ee [2] 3b c2 [2] 15 e0 [2] 01 fb [2] 0e e1 [2] 10 fc [2] 12 fd [2] 09 fb [2] 15 fc [2] 09 d3 }

  condition:
    any of them
}