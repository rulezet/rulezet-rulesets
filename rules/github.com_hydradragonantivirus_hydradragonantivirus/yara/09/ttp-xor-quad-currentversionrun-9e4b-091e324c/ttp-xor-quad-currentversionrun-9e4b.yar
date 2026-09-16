rule TTP_XOR_QUAD_CurrentVersionRun_9e4b {
  strings:
    $key_9e4b = { cd 24 [2] e9 2a [2] c2 06 [2] ec 24 [2] f8 3f [2] f7 25 [2] e9 38 [2] eb 39 [2] f0 3f [2] ec 38 [2] f0 17 }

  condition:
    any of them
}