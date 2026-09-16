rule TTP_XOR_QUAD_CurrentVersionRun_3fad {
  strings:
    $key_3fad = { 6c c2 [2] 48 cc [2] 63 e0 [2] 4d c2 [2] 59 d9 [2] 56 c3 [2] 48 de [2] 4a df [2] 51 d9 [2] 4d de [2] 51 f1 }

  condition:
    any of them
}