rule TTP_XOR_QUAD_CurrentVersionRun_a896 {
  strings:
    $key_a896 = { fb f9 [2] df f7 [2] f4 db [2] da f9 [2] ce e2 [2] c1 f8 [2] df e5 [2] dd e4 [2] c6 e2 [2] da e5 [2] c6 ca }

  condition:
    any of them
}