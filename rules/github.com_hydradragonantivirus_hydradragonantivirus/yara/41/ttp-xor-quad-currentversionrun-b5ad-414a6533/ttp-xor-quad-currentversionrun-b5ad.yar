rule TTP_XOR_QUAD_CurrentVersionRun_b5ad {
  strings:
    $key_b5ad = { e6 c2 [2] c2 cc [2] e9 e0 [2] c7 c2 [2] d3 d9 [2] dc c3 [2] c2 de [2] c0 df [2] db d9 [2] c7 de [2] db f1 }

  condition:
    any of them
}