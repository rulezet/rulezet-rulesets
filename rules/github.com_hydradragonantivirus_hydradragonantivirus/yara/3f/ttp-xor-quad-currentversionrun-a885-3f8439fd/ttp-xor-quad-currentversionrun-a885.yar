rule TTP_XOR_QUAD_CurrentVersionRun_a885 {
  strings:
    $key_a885 = { fb ea [2] df e4 [2] f4 c8 [2] da ea [2] ce f1 [2] c1 eb [2] df f6 [2] dd f7 [2] c6 f1 [2] da f6 [2] c6 d9 }

  condition:
    any of them
}