rule TTP_XOR_QUAD_CurrentVersionRun_a8d0 {
  strings:
    $key_a8d0 = { fb bf [2] df b1 [2] f4 9d [2] da bf [2] ce a4 [2] c1 be [2] df a3 [2] dd a2 [2] c6 a4 [2] da a3 [2] c6 8c }

  condition:
    any of them
}