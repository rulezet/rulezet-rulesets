rule TTP_XOR_QUAD_CurrentVersionRun_a883 {
  strings:
    $key_a883 = { fb ec [2] df e2 [2] f4 ce [2] da ec [2] ce f7 [2] c1 ed [2] df f0 [2] dd f1 [2] c6 f7 [2] da f0 [2] c6 df }

  condition:
    any of them
}