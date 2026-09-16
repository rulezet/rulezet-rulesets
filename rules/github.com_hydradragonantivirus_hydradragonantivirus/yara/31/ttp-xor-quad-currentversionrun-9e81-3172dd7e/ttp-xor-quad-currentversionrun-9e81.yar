rule TTP_XOR_QUAD_CurrentVersionRun_9e81 {
  strings:
    $key_9e81 = { cd ee [2] e9 e0 [2] c2 cc [2] ec ee [2] f8 f5 [2] f7 ef [2] e9 f2 [2] eb f3 [2] f0 f5 [2] ec f2 [2] f0 dd }

  condition:
    any of them
}