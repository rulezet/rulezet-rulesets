rule TTP_XOR_QUAD_CurrentVersionRun_9ebc {
  strings:
    $key_9ebc = { cd d3 [2] e9 dd [2] c2 f1 [2] ec d3 [2] f8 c8 [2] f7 d2 [2] e9 cf [2] eb ce [2] f0 c8 [2] ec cf [2] f0 e0 }

  condition:
    any of them
}