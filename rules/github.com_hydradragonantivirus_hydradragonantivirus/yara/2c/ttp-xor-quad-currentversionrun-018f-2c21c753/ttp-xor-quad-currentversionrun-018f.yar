rule TTP_XOR_QUAD_CurrentVersionRun_018f {
  strings:
    $key_018f = { 52 e0 [2] 76 ee [2] 5d c2 [2] 73 e0 [2] 67 fb [2] 68 e1 [2] 76 fc [2] 74 fd [2] 6f fb [2] 73 fc [2] 6f d3 }

  condition:
    any of them
}