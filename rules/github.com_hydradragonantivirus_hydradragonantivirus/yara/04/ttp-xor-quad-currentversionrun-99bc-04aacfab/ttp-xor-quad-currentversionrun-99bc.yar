rule TTP_XOR_QUAD_CurrentVersionRun_99bc {
  strings:
    $key_99bc = { ca d3 [2] ee dd [2] c5 f1 [2] eb d3 [2] ff c8 [2] f0 d2 [2] ee cf [2] ec ce [2] f7 c8 [2] eb cf [2] f7 e0 }

  condition:
    any of them
}