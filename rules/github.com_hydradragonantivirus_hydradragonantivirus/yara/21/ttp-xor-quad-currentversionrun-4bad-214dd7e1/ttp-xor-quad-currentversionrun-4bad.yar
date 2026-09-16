rule TTP_XOR_QUAD_CurrentVersionRun_4bad {
  strings:
    $key_4bad = { 18 c2 [2] 3c cc [2] 17 e0 [2] 39 c2 [2] 2d d9 [2] 22 c3 [2] 3c de [2] 3e df [2] 25 d9 [2] 39 de [2] 25 f1 }

  condition:
    any of them
}