rule TTP_XOR_QUAD_CurrentVersionRun_c9c8 {
  strings:
    $key_c9c8 = { 9a a7 [2] be a9 [2] 95 85 [2] bb a7 [2] af bc [2] a0 a6 [2] be bb [2] bc ba [2] a7 bc [2] bb bb [2] a7 94 }

  condition:
    any of them
}