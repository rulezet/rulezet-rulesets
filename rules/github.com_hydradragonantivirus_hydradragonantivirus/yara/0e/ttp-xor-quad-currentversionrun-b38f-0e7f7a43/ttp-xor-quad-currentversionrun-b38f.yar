rule TTP_XOR_QUAD_CurrentVersionRun_b38f {
  strings:
    $key_b38f = { e0 e0 [2] c4 ee [2] ef c2 [2] c1 e0 [2] d5 fb [2] da e1 [2] c4 fc [2] c6 fd [2] dd fb [2] c1 fc [2] dd d3 }

  condition:
    any of them
}