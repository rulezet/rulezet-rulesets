rule TTP_XOR_QUAD_CurrentVersionRun_32ad {
  strings:
    $key_32ad = { 61 c2 [2] 45 cc [2] 6e e0 [2] 40 c2 [2] 54 d9 [2] 5b c3 [2] 45 de [2] 47 df [2] 5c d9 [2] 40 de [2] 5c f1 }

  condition:
    any of them
}