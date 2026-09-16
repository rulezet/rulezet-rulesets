rule TTP_XOR_QUAD_CurrentVersionRun_f18f {
  strings:
    $key_f18f = { a2 e0 [2] 86 ee [2] ad c2 [2] 83 e0 [2] 97 fb [2] 98 e1 [2] 86 fc [2] 84 fd [2] 9f fb [2] 83 fc [2] 9f d3 }

  condition:
    any of them
}