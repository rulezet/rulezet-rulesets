rule TTP_XOR_QUAD_CurrentVersionRun_aad5 {
  strings:
    $key_aad5 = { f9 ba [2] dd b4 [2] f6 98 [2] d8 ba [2] cc a1 [2] c3 bb [2] dd a6 [2] df a7 [2] c4 a1 [2] d8 a6 [2] c4 89 }

  condition:
    any of them
}