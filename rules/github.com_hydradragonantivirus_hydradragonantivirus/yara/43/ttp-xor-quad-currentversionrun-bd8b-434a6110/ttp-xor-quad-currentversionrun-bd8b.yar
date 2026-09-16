rule TTP_XOR_QUAD_CurrentVersionRun_bd8b {
  strings:
    $key_bd8b = { ee e4 [2] ca ea [2] e1 c6 [2] cf e4 [2] db ff [2] d4 e5 [2] ca f8 [2] c8 f9 [2] d3 ff [2] cf f8 [2] d3 d7 }

  condition:
    any of them
}