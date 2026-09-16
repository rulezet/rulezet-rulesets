rule TTP_XOR_QUAD_CurrentVersionRun_a8cb {
  strings:
    $key_a8cb = { fb a4 [2] df aa [2] f4 86 [2] da a4 [2] ce bf [2] c1 a5 [2] df b8 [2] dd b9 [2] c6 bf [2] da b8 [2] c6 97 }

  condition:
    any of them
}