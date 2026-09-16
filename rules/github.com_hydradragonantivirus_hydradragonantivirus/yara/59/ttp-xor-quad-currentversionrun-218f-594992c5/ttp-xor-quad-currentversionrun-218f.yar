rule TTP_XOR_QUAD_CurrentVersionRun_218f {
  strings:
    $key_218f = { 72 e0 [2] 56 ee [2] 7d c2 [2] 53 e0 [2] 47 fb [2] 48 e1 [2] 56 fc [2] 54 fd [2] 4f fb [2] 53 fc [2] 4f d3 }

  condition:
    any of them
}