rule TTP_XOR_QUAD_CurrentVersionRun_a984 {
  strings:
    $key_a984 = { fa eb [2] de e5 [2] f5 c9 [2] db eb [2] cf f0 [2] c0 ea [2] de f7 [2] dc f6 [2] c7 f0 [2] db f7 [2] c7 d8 }

  condition:
    any of them
}