rule TTP_XOR_QUAD_CurrentVersionRun_1bad {
  strings:
    $key_1bad = { 48 c2 [2] 6c cc [2] 47 e0 [2] 69 c2 [2] 7d d9 [2] 72 c3 [2] 6c de [2] 6e df [2] 75 d9 [2] 69 de [2] 75 f1 }

  condition:
    any of them
}