rule TTP_XOR_QUAD_CurrentVersionRun_17ad {
  strings:
    $key_17ad = { 44 c2 [2] 60 cc [2] 4b e0 [2] 65 c2 [2] 71 d9 [2] 7e c3 [2] 60 de [2] 62 df [2] 79 d9 [2] 65 de [2] 79 f1 }

  condition:
    any of them
}