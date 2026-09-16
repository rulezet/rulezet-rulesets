rule TTP_XOR_QUAD_CurrentVersionRun_bdd7 {
  strings:
    $key_bdd7 = { ee b8 [2] ca b6 [2] e1 9a [2] cf b8 [2] db a3 [2] d4 b9 [2] ca a4 [2] c8 a5 [2] d3 a3 [2] cf a4 [2] d3 8b }

  condition:
    any of them
}