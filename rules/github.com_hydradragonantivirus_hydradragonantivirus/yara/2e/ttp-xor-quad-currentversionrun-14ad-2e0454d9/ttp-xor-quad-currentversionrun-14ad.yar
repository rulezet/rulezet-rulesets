rule TTP_XOR_QUAD_CurrentVersionRun_14ad {
  strings:
    $key_14ad = { 47 c2 [2] 63 cc [2] 48 e0 [2] 66 c2 [2] 72 d9 [2] 7d c3 [2] 63 de [2] 61 df [2] 7a d9 [2] 66 de [2] 7a f1 }

  condition:
    any of them
}