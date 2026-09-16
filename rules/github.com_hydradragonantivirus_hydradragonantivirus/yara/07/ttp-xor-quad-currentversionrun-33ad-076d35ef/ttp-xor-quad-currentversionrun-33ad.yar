rule TTP_XOR_QUAD_CurrentVersionRun_33ad {
  strings:
    $key_33ad = { 60 c2 [2] 44 cc [2] 6f e0 [2] 41 c2 [2] 55 d9 [2] 5a c3 [2] 44 de [2] 46 df [2] 5d d9 [2] 41 de [2] 5d f1 }

  condition:
    any of them
}