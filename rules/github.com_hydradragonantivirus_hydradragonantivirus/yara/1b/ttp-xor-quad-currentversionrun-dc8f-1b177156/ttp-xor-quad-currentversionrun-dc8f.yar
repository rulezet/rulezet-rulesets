rule TTP_XOR_QUAD_CurrentVersionRun_dc8f {
  strings:
    $key_dc8f = { 8f e0 [2] ab ee [2] 80 c2 [2] ae e0 [2] ba fb [2] b5 e1 [2] ab fc [2] a9 fd [2] b2 fb [2] ae fc [2] b2 d3 }

  condition:
    any of them
}