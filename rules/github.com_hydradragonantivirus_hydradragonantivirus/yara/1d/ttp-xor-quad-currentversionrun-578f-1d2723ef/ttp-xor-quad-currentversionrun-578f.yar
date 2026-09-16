rule TTP_XOR_QUAD_CurrentVersionRun_578f {
  strings:
    $key_578f = { 04 e0 [2] 20 ee [2] 0b c2 [2] 25 e0 [2] 31 fb [2] 3e e1 [2] 20 fc [2] 22 fd [2] 39 fb [2] 25 fc [2] 39 d3 }

  condition:
    any of them
}