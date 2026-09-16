rule TTP_XOR_QUAD_CurrentVersionRun_a89c {
  strings:
    $key_a89c = { fb f3 [2] df fd [2] f4 d1 [2] da f3 [2] ce e8 [2] c1 f2 [2] df ef [2] dd ee [2] c6 e8 [2] da ef [2] c6 c0 }

  condition:
    any of them
}