rule TTP_XOR_QUAD_CurrentVersionRun_91b0 {
  strings:
    $key_91b0 = { c2 df [2] e6 d1 [2] cd fd [2] e3 df [2] f7 c4 [2] f8 de [2] e6 c3 [2] e4 c2 [2] ff c4 [2] e3 c3 [2] ff ec }

  condition:
    any of them
}