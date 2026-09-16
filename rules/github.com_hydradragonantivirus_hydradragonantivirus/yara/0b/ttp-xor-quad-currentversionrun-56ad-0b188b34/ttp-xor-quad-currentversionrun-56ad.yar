rule TTP_XOR_QUAD_CurrentVersionRun_56ad {
  strings:
    $key_56ad = { 05 c2 [2] 21 cc [2] 0a e0 [2] 24 c2 [2] 30 d9 [2] 3f c3 [2] 21 de [2] 23 df [2] 38 d9 [2] 24 de [2] 38 f1 }

  condition:
    any of them
}