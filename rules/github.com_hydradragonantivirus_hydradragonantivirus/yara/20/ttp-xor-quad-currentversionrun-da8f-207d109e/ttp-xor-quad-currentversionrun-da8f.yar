rule TTP_XOR_QUAD_CurrentVersionRun_da8f {
  strings:
    $key_da8f = { 89 e0 [2] ad ee [2] 86 c2 [2] a8 e0 [2] bc fb [2] b3 e1 [2] ad fc [2] af fd [2] b4 fb [2] a8 fc [2] b4 d3 }

  condition:
    any of them
}