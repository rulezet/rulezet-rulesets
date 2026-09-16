rule TTP_XOR_QUAD_CurrentVersionRun_d5ad {
  strings:
    $key_d5ad = { 86 c2 [2] a2 cc [2] 89 e0 [2] a7 c2 [2] b3 d9 [2] bc c3 [2] a2 de [2] a0 df [2] bb d9 [2] a7 de [2] bb f1 }

  condition:
    any of them
}