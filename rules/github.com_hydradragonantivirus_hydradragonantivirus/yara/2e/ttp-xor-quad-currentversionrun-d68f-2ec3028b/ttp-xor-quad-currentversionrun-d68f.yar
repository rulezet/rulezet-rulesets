rule TTP_XOR_QUAD_CurrentVersionRun_d68f {
  strings:
    $key_d68f = { 85 e0 [2] a1 ee [2] 8a c2 [2] a4 e0 [2] b0 fb [2] bf e1 [2] a1 fc [2] a3 fd [2] b8 fb [2] a4 fc [2] b8 d3 }

  condition:
    any of them
}