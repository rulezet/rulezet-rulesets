rule TTP_XOR_QUAD_CurrentVersionRun_a893 {
  strings:
    $key_a893 = { fb fc [2] df f2 [2] f4 de [2] da fc [2] ce e7 [2] c1 fd [2] df e0 [2] dd e1 [2] c6 e7 [2] da e0 [2] c6 cf }

  condition:
    any of them
}