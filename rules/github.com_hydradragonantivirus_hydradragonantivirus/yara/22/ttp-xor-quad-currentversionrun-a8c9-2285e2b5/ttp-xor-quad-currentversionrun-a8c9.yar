rule TTP_XOR_QUAD_CurrentVersionRun_a8c9 {
  strings:
    $key_a8c9 = { fb a6 [2] df a8 [2] f4 84 [2] da a6 [2] ce bd [2] c1 a7 [2] df ba [2] dd bb [2] c6 bd [2] da ba [2] c6 95 }

  condition:
    any of them
}