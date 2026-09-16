rule TTP_XOR_QUAD_CurrentVersionRun_20ad {
  strings:
    $key_20ad = { 73 c2 [2] 57 cc [2] 7c e0 [2] 52 c2 [2] 46 d9 [2] 49 c3 [2] 57 de [2] 55 df [2] 4e d9 [2] 52 de [2] 4e f1 }

  condition:
    any of them
}