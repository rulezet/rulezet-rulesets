rule TTP_XOR_QUAD_CurrentVersionRun_a98b {
  strings:
    $key_a98b = { fa e4 [2] de ea [2] f5 c6 [2] db e4 [2] cf ff [2] c0 e5 [2] de f8 [2] dc f9 [2] c7 ff [2] db f8 [2] c7 d7 }

  condition:
    any of them
}