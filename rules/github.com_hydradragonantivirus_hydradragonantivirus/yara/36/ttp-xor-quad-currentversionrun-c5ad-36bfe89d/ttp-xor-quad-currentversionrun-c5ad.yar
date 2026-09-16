rule TTP_XOR_QUAD_CurrentVersionRun_c5ad {
  strings:
    $key_c5ad = { 96 c2 [2] b2 cc [2] 99 e0 [2] b7 c2 [2] a3 d9 [2] ac c3 [2] b2 de [2] b0 df [2] ab d9 [2] b7 de [2] ab f1 }

  condition:
    any of them
}