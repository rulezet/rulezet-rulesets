rule TTP_XOR_QUAD_CurrentVersionRun_d48f {
  strings:
    $key_d48f = { 87 e0 [2] a3 ee [2] 88 c2 [2] a6 e0 [2] b2 fb [2] bd e1 [2] a3 fc [2] a1 fd [2] ba fb [2] a6 fc [2] ba d3 }

  condition:
    any of them
}