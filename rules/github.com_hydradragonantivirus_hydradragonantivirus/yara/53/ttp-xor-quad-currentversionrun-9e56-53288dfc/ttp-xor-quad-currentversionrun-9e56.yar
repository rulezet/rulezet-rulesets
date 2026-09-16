rule TTP_XOR_QUAD_CurrentVersionRun_9e56 {
  strings:
    $key_9e56 = { cd 39 [2] e9 37 [2] c2 1b [2] ec 39 [2] f8 22 [2] f7 38 [2] e9 25 [2] eb 24 [2] f0 22 [2] ec 25 [2] f0 0a }

  condition:
    any of them
}