rule TTP_XOR_QUAD_CurrentVersionRun_afd5 {
  strings:
    $key_afd5 = { fc ba [2] d8 b4 [2] f3 98 [2] dd ba [2] c9 a1 [2] c6 bb [2] d8 a6 [2] da a7 [2] c1 a1 [2] dd a6 [2] c1 89 }

  condition:
    any of them
}