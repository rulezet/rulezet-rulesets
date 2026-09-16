rule TTP_XOR_QUAD_CurrentVersionRun_bfb0 {
  strings:
    $key_bfb0 = { ec df [2] c8 d1 [2] e3 fd [2] cd df [2] d9 c4 [2] d6 de [2] c8 c3 [2] ca c2 [2] d1 c4 [2] cd c3 [2] d1 ec }

  condition:
    any of them
}