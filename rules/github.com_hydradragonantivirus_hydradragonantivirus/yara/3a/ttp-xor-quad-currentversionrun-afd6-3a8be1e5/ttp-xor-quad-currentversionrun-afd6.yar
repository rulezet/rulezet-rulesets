rule TTP_XOR_QUAD_CurrentVersionRun_afd6 {
  strings:
    $key_afd6 = { fc b9 [2] d8 b7 [2] f3 9b [2] dd b9 [2] c9 a2 [2] c6 b8 [2] d8 a5 [2] da a4 [2] c1 a2 [2] dd a5 [2] c1 8a }

  condition:
    any of them
}