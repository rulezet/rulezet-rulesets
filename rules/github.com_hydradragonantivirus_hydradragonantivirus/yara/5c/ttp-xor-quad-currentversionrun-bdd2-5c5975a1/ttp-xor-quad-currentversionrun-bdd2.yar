rule TTP_XOR_QUAD_CurrentVersionRun_bdd2 {
  strings:
    $key_bdd2 = { ee bd [2] ca b3 [2] e1 9f [2] cf bd [2] db a6 [2] d4 bc [2] ca a1 [2] c8 a0 [2] d3 a6 [2] cf a1 [2] d3 8e }

  condition:
    any of them
}