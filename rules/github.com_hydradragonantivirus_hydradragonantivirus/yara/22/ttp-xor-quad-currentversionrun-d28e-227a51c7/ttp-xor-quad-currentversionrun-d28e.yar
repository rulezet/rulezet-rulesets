rule TTP_XOR_QUAD_CurrentVersionRun_d28e {
  strings:
    $key_d28e = { 81 e1 [2] a5 ef [2] 8e c3 [2] a0 e1 [2] b4 fa [2] bb e0 [2] a5 fd [2] a7 fc [2] bc fa [2] a0 fd [2] bc d2 }

  condition:
    any of them
}