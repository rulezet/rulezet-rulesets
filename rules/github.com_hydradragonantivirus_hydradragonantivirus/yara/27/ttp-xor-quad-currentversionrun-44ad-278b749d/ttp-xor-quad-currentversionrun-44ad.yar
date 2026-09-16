rule TTP_XOR_QUAD_CurrentVersionRun_44ad {
  strings:
    $key_44ad = { 17 c2 [2] 33 cc [2] 18 e0 [2] 36 c2 [2] 22 d9 [2] 2d c3 [2] 33 de [2] 31 df [2] 2a d9 [2] 36 de [2] 2a f1 }

  condition:
    any of them
}