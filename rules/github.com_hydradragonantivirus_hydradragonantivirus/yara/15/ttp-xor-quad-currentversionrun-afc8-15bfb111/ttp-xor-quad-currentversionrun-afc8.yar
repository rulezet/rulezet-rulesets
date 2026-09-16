rule TTP_XOR_QUAD_CurrentVersionRun_afc8 {
  strings:
    $key_afc8 = { fc a7 [2] d8 a9 [2] f3 85 [2] dd a7 [2] c9 bc [2] c6 a6 [2] d8 bb [2] da ba [2] c1 bc [2] dd bb [2] c1 94 }

  condition:
    any of them
}