rule TTP_XOR_QUAD_CurrentVersionRun_bfad {
  strings:
    $key_bfad = { ec c2 [2] c8 cc [2] e3 e0 [2] cd c2 [2] d9 d9 [2] d6 c3 [2] c8 de [2] ca df [2] d1 d9 [2] cd de [2] d1 f1 }

  condition:
    any of them
}