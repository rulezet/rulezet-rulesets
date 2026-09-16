rule TTP_XOR_QUAD_CurrentVersionRun_f48f {
  strings:
    $key_f48f = { a7 e0 [2] 83 ee [2] a8 c2 [2] 86 e0 [2] 92 fb [2] 9d e1 [2] 83 fc [2] 81 fd [2] 9a fb [2] 86 fc [2] 9a d3 }

  condition:
    any of them
}