rule TTP_XOR_QUAD_CurrentVersionRun_51ad {
  strings:
    $key_51ad = { 02 c2 [2] 26 cc [2] 0d e0 [2] 23 c2 [2] 37 d9 [2] 38 c3 [2] 26 de [2] 24 df [2] 3f d9 [2] 23 de [2] 3f f1 }

  condition:
    any of them
}