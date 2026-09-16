rule TTP_XOR_QUAD_CurrentVersionRun_7fad {
  strings:
    $key_7fad = { 2c c2 [2] 08 cc [2] 23 e0 [2] 0d c2 [2] 19 d9 [2] 16 c3 [2] 08 de [2] 0a df [2] 11 d9 [2] 0d de [2] 11 f1 }

  condition:
    any of them
}