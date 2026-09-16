rule TTP_XOR_QUAD_CurrentVersionRun_67ad {
  strings:
    $key_67ad = { 34 c2 [2] 10 cc [2] 3b e0 [2] 15 c2 [2] 01 d9 [2] 0e c3 [2] 10 de [2] 12 df [2] 09 d9 [2] 15 de [2] 09 f1 }

  condition:
    any of them
}