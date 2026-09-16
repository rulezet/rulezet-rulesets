rule TTP_XOR_QUAD_CurrentVersionRun_bab0 {
  strings:
    $key_bab0 = { e9 df [2] cd d1 [2] e6 fd [2] c8 df [2] dc c4 [2] d3 de [2] cd c3 [2] cf c2 [2] d4 c4 [2] c8 c3 [2] d4 ec }

  condition:
    any of them
}