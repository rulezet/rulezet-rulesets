rule TTP_XOR_QUAD_CurrentVersionRun_9ead {
  strings:
    $key_9ead = { cd c2 [2] e9 cc [2] c2 e0 [2] ec c2 [2] f8 d9 [2] f7 c3 [2] e9 de [2] eb df [2] f0 d9 [2] ec de [2] f0 f1 }

  condition:
    any of them
}