rule TTP_XOR_QUAD_CurrentVersionRun_9e76 {
  strings:
    $key_9e76 = { cd 19 [2] e9 17 [2] c2 3b [2] ec 19 [2] f8 02 [2] f7 18 [2] e9 05 [2] eb 04 [2] f0 02 [2] ec 05 [2] f0 2a }

  condition:
    any of them
}