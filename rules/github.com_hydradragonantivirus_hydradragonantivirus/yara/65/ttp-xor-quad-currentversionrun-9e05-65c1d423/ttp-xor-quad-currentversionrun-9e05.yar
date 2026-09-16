rule TTP_XOR_QUAD_CurrentVersionRun_9e05 {
  strings:
    $key_9e05 = { cd 6a [2] e9 64 [2] c2 48 [2] ec 6a [2] f8 71 [2] f7 6b [2] e9 76 [2] eb 77 [2] f0 71 [2] ec 76 [2] f0 59 }

  condition:
    any of them
}