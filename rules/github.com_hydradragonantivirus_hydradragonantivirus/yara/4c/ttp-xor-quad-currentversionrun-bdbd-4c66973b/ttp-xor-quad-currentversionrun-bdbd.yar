rule TTP_XOR_QUAD_CurrentVersionRun_bdbd {
  strings:
    $key_bdbd = { ee d2 [2] ca dc [2] e1 f0 [2] cf d2 [2] db c9 [2] d4 d3 [2] ca ce [2] c8 cf [2] d3 c9 [2] cf ce [2] d3 e1 }

  condition:
    any of them
}