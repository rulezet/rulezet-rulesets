rule TTP_XOR_QUAD_CurrentVersionRun_bdaf {
  strings:
    $key_bdaf = { ee c0 [2] ca ce [2] e1 e2 [2] cf c0 [2] db db [2] d4 c1 [2] ca dc [2] c8 dd [2] d3 db [2] cf dc [2] d3 f3 }

  condition:
    any of them
}