rule TTP_XOR_QUAD_CurrentVersionRun_058f {
  strings:
    $key_058f = { 56 e0 [2] 72 ee [2] 59 c2 [2] 77 e0 [2] 63 fb [2] 6c e1 [2] 72 fc [2] 70 fd [2] 6b fb [2] 77 fc [2] 6b d3 }

  condition:
    any of them
}