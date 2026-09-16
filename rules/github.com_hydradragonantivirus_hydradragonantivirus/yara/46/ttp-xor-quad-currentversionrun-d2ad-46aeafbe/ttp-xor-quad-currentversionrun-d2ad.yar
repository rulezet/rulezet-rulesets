rule TTP_XOR_QUAD_CurrentVersionRun_d2ad {
  strings:
    $key_d2ad = { 81 c2 [2] a5 cc [2] 8e e0 [2] a0 c2 [2] b4 d9 [2] bb c3 [2] a5 de [2] a7 df [2] bc d9 [2] a0 de [2] bc f1 }

  condition:
    any of them
}