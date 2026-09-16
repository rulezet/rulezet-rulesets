rule TTP_XOR_QUAD_CurrentVersionRun_9e18 {
  strings:
    $key_9e18 = { cd 77 [2] e9 79 [2] c2 55 [2] ec 77 [2] f8 6c [2] f7 76 [2] e9 6b [2] eb 6a [2] f0 6c [2] ec 6b [2] f0 44 }

  condition:
    any of them
}