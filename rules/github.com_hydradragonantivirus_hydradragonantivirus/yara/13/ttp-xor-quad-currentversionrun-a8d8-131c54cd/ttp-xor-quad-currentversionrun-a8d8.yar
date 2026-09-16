rule TTP_XOR_QUAD_CurrentVersionRun_a8d8 {
  strings:
    $key_a8d8 = { fb b7 [2] df b9 [2] f4 95 [2] da b7 [2] ce ac [2] c1 b6 [2] df ab [2] dd aa [2] c6 ac [2] da ab [2] c6 84 }

  condition:
    any of them
}