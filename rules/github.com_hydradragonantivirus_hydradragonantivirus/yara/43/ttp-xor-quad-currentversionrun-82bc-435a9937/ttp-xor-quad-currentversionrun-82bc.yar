rule TTP_XOR_QUAD_CurrentVersionRun_82bc {
  strings:
    $key_82bc = { d1 d3 [2] f5 dd [2] de f1 [2] f0 d3 [2] e4 c8 [2] eb d2 [2] f5 cf [2] f7 ce [2] ec c8 [2] f0 cf [2] ec e0 }

  condition:
    any of them
}