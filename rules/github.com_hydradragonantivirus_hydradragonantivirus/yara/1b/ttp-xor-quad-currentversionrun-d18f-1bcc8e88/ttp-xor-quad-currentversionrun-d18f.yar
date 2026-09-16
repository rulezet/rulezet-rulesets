rule TTP_XOR_QUAD_CurrentVersionRun_d18f {
  strings:
    $key_d18f = { 82 e0 [2] a6 ee [2] 8d c2 [2] a3 e0 [2] b7 fb [2] b8 e1 [2] a6 fc [2] a4 fd [2] bf fb [2] a3 fc [2] bf d3 }

  condition:
    any of them
}