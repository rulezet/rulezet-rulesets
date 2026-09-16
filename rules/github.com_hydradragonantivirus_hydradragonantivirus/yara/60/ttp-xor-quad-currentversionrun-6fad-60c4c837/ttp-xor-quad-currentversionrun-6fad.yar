rule TTP_XOR_QUAD_CurrentVersionRun_6fad {
  strings:
    $key_6fad = { 3c c2 [2] 18 cc [2] 33 e0 [2] 1d c2 [2] 09 d9 [2] 06 c3 [2] 18 de [2] 1a df [2] 01 d9 [2] 1d de [2] 01 f1 }

  condition:
    any of them
}