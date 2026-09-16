rule TTP_XOR_QUAD_CurrentVersionRun_9e06 {
  strings:
    $key_9e06 = { cd 69 [2] e9 67 [2] c2 4b [2] ec 69 [2] f8 72 [2] f7 68 [2] e9 75 [2] eb 74 [2] f0 72 [2] ec 75 [2] f0 5a }

  condition:
    any of them
}