rule TTP_XOR_QUAD_CurrentVersionRun_bdbb {
  strings:
    $key_bdbb = { ee d4 [2] ca da [2] e1 f6 [2] cf d4 [2] db cf [2] d4 d5 [2] ca c8 [2] c8 c9 [2] d3 cf [2] cf c8 [2] d3 e7 }

  condition:
    any of them
}