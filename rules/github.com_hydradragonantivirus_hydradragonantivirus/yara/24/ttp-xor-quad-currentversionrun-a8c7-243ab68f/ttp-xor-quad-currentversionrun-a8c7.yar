rule TTP_XOR_QUAD_CurrentVersionRun_a8c7 {
  strings:
    $key_a8c7 = { fb a8 [2] df a6 [2] f4 8a [2] da a8 [2] ce b3 [2] c1 a9 [2] df b4 [2] dd b5 [2] c6 b3 [2] da b4 [2] c6 9b }

  condition:
    any of them
}