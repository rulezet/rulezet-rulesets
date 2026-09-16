rule TTP_XOR_QUAD_CurrentVersionRun_d78f {
  strings:
    $key_d78f = { 84 e0 [2] a0 ee [2] 8b c2 [2] a5 e0 [2] b1 fb [2] be e1 [2] a0 fc [2] a2 fd [2] b9 fb [2] a5 fc [2] b9 d3 }

  condition:
    any of them
}