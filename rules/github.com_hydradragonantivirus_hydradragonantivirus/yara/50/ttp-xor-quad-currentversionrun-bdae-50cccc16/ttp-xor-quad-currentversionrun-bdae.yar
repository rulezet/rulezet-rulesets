rule TTP_XOR_QUAD_CurrentVersionRun_bdae {
  strings:
    $key_bdae = { ee c1 [2] ca cf [2] e1 e3 [2] cf c1 [2] db da [2] d4 c0 [2] ca dd [2] c8 dc [2] d3 da [2] cf dd [2] d3 f2 }

  condition:
    any of them
}