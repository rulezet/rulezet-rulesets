rule TTP_XOR_QUAD_CurrentVersionRun_9e68 {
  strings:
    $key_9e68 = { cd 07 [2] e9 09 [2] c2 25 [2] ec 07 [2] f8 1c [2] f7 06 [2] e9 1b [2] eb 1a [2] f0 1c [2] ec 1b [2] f0 34 }

  condition:
    any of them
}