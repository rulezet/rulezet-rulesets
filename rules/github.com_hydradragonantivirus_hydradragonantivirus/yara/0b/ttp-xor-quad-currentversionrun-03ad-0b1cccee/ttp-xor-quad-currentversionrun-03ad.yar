rule TTP_XOR_QUAD_CurrentVersionRun_03ad {
  strings:
    $key_03ad = { 50 c2 [2] 74 cc [2] 5f e0 [2] 71 c2 [2] 65 d9 [2] 6a c3 [2] 74 de [2] 76 df [2] 6d d9 [2] 71 de [2] 6d f1 }

  condition:
    any of them
}