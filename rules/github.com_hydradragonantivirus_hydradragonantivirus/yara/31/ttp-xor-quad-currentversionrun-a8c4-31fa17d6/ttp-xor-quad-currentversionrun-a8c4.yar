rule TTP_XOR_QUAD_CurrentVersionRun_a8c4 {
  strings:
    $key_a8c4 = { fb ab [2] df a5 [2] f4 89 [2] da ab [2] ce b0 [2] c1 aa [2] df b7 [2] dd b6 [2] c6 b0 [2] da b7 [2] c6 98 }

  condition:
    any of them
}