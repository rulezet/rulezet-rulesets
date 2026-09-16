rule TTP_XOR_QUAD_CurrentVersionRun_abb0 {
  strings:
    $key_abb0 = { f8 df [2] dc d1 [2] f7 fd [2] d9 df [2] cd c4 [2] c2 de [2] dc c3 [2] de c2 [2] c5 c4 [2] d9 c3 [2] c5 ec }

  condition:
    any of them
}