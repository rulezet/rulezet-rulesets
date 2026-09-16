rule TTP_XOR_QUAD_CurrentVersionRun_a8d9 {
  strings:
    $key_a8d9 = { fb b6 [2] df b8 [2] f4 94 [2] da b6 [2] ce ad [2] c1 b7 [2] df aa [2] dd ab [2] c6 ad [2] da aa [2] c6 85 }

  condition:
    any of them
}