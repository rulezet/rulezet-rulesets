rule TTP_XOR_QUAD_CurrentVersionRun_9ebd {
  strings:
    $key_9ebd = { cd d2 [2] e9 dc [2] c2 f0 [2] ec d2 [2] f8 c9 [2] f7 d3 [2] e9 ce [2] eb cf [2] f0 c9 [2] ec ce [2] f0 e1 }

  condition:
    any of them
}