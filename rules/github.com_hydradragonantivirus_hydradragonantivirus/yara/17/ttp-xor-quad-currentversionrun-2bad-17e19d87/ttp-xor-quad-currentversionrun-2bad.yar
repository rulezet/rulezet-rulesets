rule TTP_XOR_QUAD_CurrentVersionRun_2bad {
  strings:
    $key_2bad = { 78 c2 [2] 5c cc [2] 77 e0 [2] 59 c2 [2] 4d d9 [2] 42 c3 [2] 5c de [2] 5e df [2] 45 d9 [2] 59 de [2] 45 f1 }

  condition:
    any of them
}