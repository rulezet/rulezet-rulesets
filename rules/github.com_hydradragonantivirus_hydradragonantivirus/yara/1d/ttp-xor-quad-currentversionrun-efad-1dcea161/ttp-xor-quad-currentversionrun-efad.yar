rule TTP_XOR_QUAD_CurrentVersionRun_efad {
  strings:
    $key_efad = { bc c2 [2] 98 cc [2] b3 e0 [2] 9d c2 [2] 89 d9 [2] 86 c3 [2] 98 de [2] 9a df [2] 81 d9 [2] 9d de [2] 81 f1 }

  condition:
    any of them
}