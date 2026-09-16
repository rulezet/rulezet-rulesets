rule TTP_XOR_QUAD_CurrentVersionRun_9e77 {
  strings:
    $key_9e77 = { cd 18 [2] e9 16 [2] c2 3a [2] ec 18 [2] f8 03 [2] f7 19 [2] e9 04 [2] eb 05 [2] f0 03 [2] ec 04 [2] f0 2b }

  condition:
    any of them
}