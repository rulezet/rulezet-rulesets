rule TTP_XOR_QUAD_CurrentVersionRun_47ad {
  strings:
    $key_47ad = { 14 c2 [2] 30 cc [2] 1b e0 [2] 35 c2 [2] 21 d9 [2] 2e c3 [2] 30 de [2] 32 df [2] 29 d9 [2] 35 de [2] 29 f1 }

  condition:
    any of them
}