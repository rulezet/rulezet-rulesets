rule TTP_XOR_QUAD_CurrentVersionRun_9ab0 {
  strings:
    $key_9ab0 = { c9 df [2] ed d1 [2] c6 fd [2] e8 df [2] fc c4 [2] f3 de [2] ed c3 [2] ef c2 [2] f4 c4 [2] e8 c3 [2] f4 ec }

  condition:
    any of them
}