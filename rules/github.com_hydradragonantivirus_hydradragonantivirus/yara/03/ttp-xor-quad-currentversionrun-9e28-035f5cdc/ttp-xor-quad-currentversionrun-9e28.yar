rule TTP_XOR_QUAD_CurrentVersionRun_9e28 {
  strings:
    $key_9e28 = { cd 47 [2] e9 49 [2] c2 65 [2] ec 47 [2] f8 5c [2] f7 46 [2] e9 5b [2] eb 5a [2] f0 5c [2] ec 5b [2] f0 74 }

  condition:
    any of them
}