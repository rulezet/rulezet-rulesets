rule TTP_XOR_QUAD_CurrentVersionRun_bbd4 {
  strings:
    $key_bbd4 = { e8 bb [2] cc b5 [2] e7 99 [2] c9 bb [2] dd a0 [2] d2 ba [2] cc a7 [2] ce a6 [2] d5 a0 [2] c9 a7 [2] d5 88 }

  condition:
    any of them
}