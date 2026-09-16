rule TTP_XOR_QUAD_CurrentVersionRun_5aad {
  strings:
    $key_5aad = { 09 c2 [2] 2d cc [2] 06 e0 [2] 28 c2 [2] 3c d9 [2] 33 c3 [2] 2d de [2] 2f df [2] 34 d9 [2] 28 de [2] 34 f1 }

  condition:
    any of them
}