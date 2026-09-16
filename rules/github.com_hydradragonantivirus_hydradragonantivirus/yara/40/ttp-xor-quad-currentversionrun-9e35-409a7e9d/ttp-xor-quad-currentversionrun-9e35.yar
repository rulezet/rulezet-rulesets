rule TTP_XOR_QUAD_CurrentVersionRun_9e35 {
  strings:
    $key_9e35 = { cd 5a [2] e9 54 [2] c2 78 [2] ec 5a [2] f8 41 [2] f7 5b [2] e9 46 [2] eb 47 [2] f0 41 [2] ec 46 [2] f0 69 }

  condition:
    any of them
}