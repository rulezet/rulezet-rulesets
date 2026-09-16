rule TTP_XOR_QUAD_CurrentVersionRun_9ebb {
  strings:
    $key_9ebb = { cd d4 [2] e9 da [2] c2 f6 [2] ec d4 [2] f8 cf [2] f7 d5 [2] e9 c8 [2] eb c9 [2] f0 cf [2] ec c8 [2] f0 e7 }

  condition:
    any of them
}