rule TTP_XOR_QUAD_CurrentVersionRun_24ad {
  strings:
    $key_24ad = { 77 c2 [2] 53 cc [2] 78 e0 [2] 56 c2 [2] 42 d9 [2] 4d c3 [2] 53 de [2] 51 df [2] 4a d9 [2] 56 de [2] 4a f1 }

  condition:
    any of them
}