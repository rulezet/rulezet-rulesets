rule TTP_XOR_QUAD_CurrentVersionRun_57ad {
  strings:
    $key_57ad = { 04 c2 [2] 20 cc [2] 0b e0 [2] 25 c2 [2] 31 d9 [2] 3e c3 [2] 20 de [2] 22 df [2] 39 d9 [2] 25 de [2] 39 f1 }

  condition:
    any of them
}