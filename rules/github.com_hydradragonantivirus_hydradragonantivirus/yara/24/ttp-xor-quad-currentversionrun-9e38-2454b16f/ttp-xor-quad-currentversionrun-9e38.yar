rule TTP_XOR_QUAD_CurrentVersionRun_9e38 {
  strings:
    $key_9e38 = { cd 57 [2] e9 59 [2] c2 75 [2] ec 57 [2] f8 4c [2] f7 56 [2] e9 4b [2] eb 4a [2] f0 4c [2] ec 4b [2] f0 64 }

  condition:
    any of them
}