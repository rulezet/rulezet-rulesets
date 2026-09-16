rule TTP_XOR_QUAD_CurrentVersionRun_5fad {
  strings:
    $key_5fad = { 0c c2 [2] 28 cc [2] 03 e0 [2] 2d c2 [2] 39 d9 [2] 36 c3 [2] 28 de [2] 2a df [2] 31 d9 [2] 2d de [2] 31 f1 }

  condition:
    any of them
}