rule TTP_XOR_QUAD_CurrentVersionRun_9e74 {
  strings:
    $key_9e74 = { cd 1b [2] e9 15 [2] c2 39 [2] ec 1b [2] f8 00 [2] f7 1a [2] e9 07 [2] eb 06 [2] f0 00 [2] ec 07 [2] f0 28 }

  condition:
    any of them
}