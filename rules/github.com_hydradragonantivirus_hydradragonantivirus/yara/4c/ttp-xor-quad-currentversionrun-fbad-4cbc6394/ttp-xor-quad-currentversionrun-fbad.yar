rule TTP_XOR_QUAD_CurrentVersionRun_fbad {
  strings:
    $key_fbad = { a8 c2 [2] 8c cc [2] a7 e0 [2] 89 c2 [2] 9d d9 [2] 92 c3 [2] 8c de [2] 8e df [2] 95 d9 [2] 89 de [2] 95 f1 }

  condition:
    any of them
}