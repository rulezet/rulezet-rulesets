rule TTP_XOR_QUAD_CurrentVersionRun_faad {
  strings:
    $key_faad = { a9 c2 [2] 8d cc [2] a6 e0 [2] 88 c2 [2] 9c d9 [2] 93 c3 [2] 8d de [2] 8f df [2] 94 d9 [2] 88 de [2] 94 f1 }

  condition:
    any of them
}