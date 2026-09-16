rule TTP_XOR_QUAD_CurrentVersionRun_3bad {
  strings:
    $key_3bad = { 68 c2 [2] 4c cc [2] 67 e0 [2] 49 c2 [2] 5d d9 [2] 52 c3 [2] 4c de [2] 4e df [2] 55 d9 [2] 49 de [2] 55 f1 }

  condition:
    any of them
}