rule TTP_XOR_QUAD_CurrentVersionRun_4aad {
  strings:
    $key_4aad = { 19 c2 [2] 3d cc [2] 16 e0 [2] 38 c2 [2] 2c d9 [2] 23 c3 [2] 3d de [2] 3f df [2] 24 d9 [2] 38 de [2] 24 f1 }

  condition:
    any of them
}