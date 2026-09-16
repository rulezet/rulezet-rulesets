rule TTP_XOR_QUAD_CurrentVersionRun_80bc {
  strings:
    $key_80bc = { d3 d3 [2] f7 dd [2] dc f1 [2] f2 d3 [2] e6 c8 [2] e9 d2 [2] f7 cf [2] f5 ce [2] ee c8 [2] f2 cf [2] ee e0 }

  condition:
    any of them
}