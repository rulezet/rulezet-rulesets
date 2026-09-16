rule TTP_XOR_QUAD_CurrentVersionRun_bdd4 {
  strings:
    $key_bdd4 = { ee bb [2] ca b5 [2] e1 99 [2] cf bb [2] db a0 [2] d4 ba [2] ca a7 [2] c8 a6 [2] d3 a0 [2] cf a7 [2] d3 88 }

  condition:
    any of them
}