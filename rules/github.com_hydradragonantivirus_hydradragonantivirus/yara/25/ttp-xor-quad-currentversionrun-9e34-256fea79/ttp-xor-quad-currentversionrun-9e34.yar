rule TTP_XOR_QUAD_CurrentVersionRun_9e34 {
  strings:
    $key_9e34 = { cd 5b [2] e9 55 [2] c2 79 [2] ec 5b [2] f8 40 [2] f7 5a [2] e9 47 [2] eb 46 [2] f0 40 [2] ec 47 [2] f0 68 }

  condition:
    any of them
}