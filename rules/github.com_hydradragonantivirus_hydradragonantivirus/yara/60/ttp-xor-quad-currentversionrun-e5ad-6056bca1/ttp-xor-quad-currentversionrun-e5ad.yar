rule TTP_XOR_QUAD_CurrentVersionRun_e5ad {
  strings:
    $key_e5ad = { b6 c2 [2] 92 cc [2] b9 e0 [2] 97 c2 [2] 83 d9 [2] 8c c3 [2] 92 de [2] 90 df [2] 8b d9 [2] 97 de [2] 8b f1 }

  condition:
    any of them
}