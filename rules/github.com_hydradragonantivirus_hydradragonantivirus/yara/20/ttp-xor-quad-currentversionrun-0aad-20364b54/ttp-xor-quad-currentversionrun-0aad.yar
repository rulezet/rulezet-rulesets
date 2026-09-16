rule TTP_XOR_QUAD_CurrentVersionRun_0aad {
  strings:
    $key_0aad = { 59 c2 [2] 7d cc [2] 56 e0 [2] 78 c2 [2] 6c d9 [2] 63 c3 [2] 7d de [2] 7f df [2] 64 d9 [2] 78 de [2] 64 f1 }

  condition:
    any of them
}