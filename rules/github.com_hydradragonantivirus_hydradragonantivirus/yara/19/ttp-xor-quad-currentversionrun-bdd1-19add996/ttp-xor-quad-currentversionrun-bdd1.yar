rule TTP_XOR_QUAD_CurrentVersionRun_bdd1 {
  strings:
    $key_bdd1 = { ee be [2] ca b0 [2] e1 9c [2] cf be [2] db a5 [2] d4 bf [2] ca a2 [2] c8 a3 [2] d3 a5 [2] cf a2 [2] d3 8d }

  condition:
    any of them
}