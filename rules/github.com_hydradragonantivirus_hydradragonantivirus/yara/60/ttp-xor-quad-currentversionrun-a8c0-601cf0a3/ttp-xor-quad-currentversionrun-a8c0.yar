rule TTP_XOR_QUAD_CurrentVersionRun_a8c0 {
  strings:
    $key_a8c0 = { fb af [2] df a1 [2] f4 8d [2] da af [2] ce b4 [2] c1 ae [2] df b3 [2] dd b2 [2] c6 b4 [2] da b3 [2] c6 9c }

  condition:
    any of them
}