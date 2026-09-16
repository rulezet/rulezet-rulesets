rule TTP_XOR_QUAD_CurrentVersionRun_bdb5 {
  strings:
    $key_bdb5 = { ee da [2] ca d4 [2] e1 f8 [2] cf da [2] db c1 [2] d4 db [2] ca c6 [2] c8 c7 [2] d3 c1 [2] cf c6 [2] d3 e9 }

  condition:
    any of them
}