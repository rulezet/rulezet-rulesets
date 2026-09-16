rule TTP_XOR_QUAD_CurrentVersionRun_43ad {
  strings:
    $key_43ad = { 10 c2 [2] 34 cc [2] 1f e0 [2] 31 c2 [2] 25 d9 [2] 2a c3 [2] 34 de [2] 36 df [2] 2d d9 [2] 31 de [2] 2d f1 }

  condition:
    any of them
}