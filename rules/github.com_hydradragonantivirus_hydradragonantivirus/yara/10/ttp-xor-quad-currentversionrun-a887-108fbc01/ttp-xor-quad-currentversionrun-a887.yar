rule TTP_XOR_QUAD_CurrentVersionRun_a887 {
  strings:
    $key_a887 = { fb e8 [2] df e6 [2] f4 ca [2] da e8 [2] ce f3 [2] c1 e9 [2] df f4 [2] dd f5 [2] c6 f3 [2] da f4 [2] c6 db }

  condition:
    any of them
}