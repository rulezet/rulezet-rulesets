rule TTP_XOR_QUAD_CurrentVersionRun_d28a {
  strings:
    $key_d28a = { 81 e5 [2] a5 eb [2] 8e c7 [2] a0 e5 [2] b4 fe [2] bb e4 [2] a5 f9 [2] a7 f8 [2] bc fe [2] a0 f9 [2] bc d6 }

  condition:
    any of them
}