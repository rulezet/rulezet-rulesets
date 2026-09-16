rule TTP_XOR_QUAD_CurrentVersionRun_a8c5 {
  strings:
    $key_a8c5 = { fb aa [2] df a4 [2] f4 88 [2] da aa [2] ce b1 [2] c1 ab [2] df b6 [2] dd b7 [2] c6 b1 [2] da b6 [2] c6 99 }

  condition:
    any of them
}