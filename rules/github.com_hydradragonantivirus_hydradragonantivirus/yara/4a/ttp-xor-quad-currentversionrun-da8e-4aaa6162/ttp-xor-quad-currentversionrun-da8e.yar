rule TTP_XOR_QUAD_CurrentVersionRun_da8e {
  strings:
    $key_da8e = { 89 e1 [2] ad ef [2] 86 c3 [2] a8 e1 [2] bc fa [2] b3 e0 [2] ad fd [2] af fc [2] b4 fa [2] a8 fd [2] b4 d2 }

  condition:
    any of them
}