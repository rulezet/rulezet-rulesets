rule TTP_XOR_QUAD_CurrentVersionRun_23ad {
  strings:
    $key_23ad = { 70 c2 [2] 54 cc [2] 7f e0 [2] 51 c2 [2] 45 d9 [2] 4a c3 [2] 54 de [2] 56 df [2] 4d d9 [2] 51 de [2] 4d f1 }

  condition:
    any of them
}