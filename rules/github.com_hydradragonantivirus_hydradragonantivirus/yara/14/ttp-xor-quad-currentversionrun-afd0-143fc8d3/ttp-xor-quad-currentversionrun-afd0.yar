rule TTP_XOR_QUAD_CurrentVersionRun_afd0 {
  strings:
    $key_afd0 = { fc bf [2] d8 b1 [2] f3 9d [2] dd bf [2] c9 a4 [2] c6 be [2] d8 a3 [2] da a2 [2] c1 a4 [2] dd a3 [2] c1 8c }

  condition:
    any of them
}