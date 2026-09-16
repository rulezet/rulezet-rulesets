rule TTP_XOR_QUAD_CurrentVersionRun_a8ca {
  strings:
    $key_a8ca = { fb a5 [2] df ab [2] f4 87 [2] da a5 [2] ce be [2] c1 a4 [2] df b9 [2] dd b8 [2] c6 be [2] da b9 [2] c6 96 }

  condition:
    any of them
}