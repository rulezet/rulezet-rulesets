rule TTP_XOR_QUAD_CurrentVersionRun_a88d {
  strings:
    $key_a88d = { fb e2 [2] df ec [2] f4 c0 [2] da e2 [2] ce f9 [2] c1 e3 [2] df fe [2] dd ff [2] c6 f9 [2] da fe [2] c6 d1 }

  condition:
    any of them
}