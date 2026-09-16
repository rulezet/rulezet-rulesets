rule TTP_XOR_QUAD_CurrentVersionRun_f3ad {
  strings:
    $key_f3ad = { a0 c2 [2] 84 cc [2] af e0 [2] 81 c2 [2] 95 d9 [2] 9a c3 [2] 84 de [2] 86 df [2] 9d d9 [2] 81 de [2] 9d f1 }

  condition:
    any of them
}