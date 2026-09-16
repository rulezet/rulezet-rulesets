rule TTP_XOR_QUAD_CurrentVersionRun_bbd7 {
  strings:
    $key_bbd7 = { e8 b8 [2] cc b6 [2] e7 9a [2] c9 b8 [2] dd a3 [2] d2 b9 [2] cc a4 [2] ce a5 [2] d5 a3 [2] c9 a4 [2] d5 8b }

  condition:
    any of them
}