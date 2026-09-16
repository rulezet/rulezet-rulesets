rule TTP_XOR_QUAD_CurrentVersionRun_9e55 {
  strings:
    $key_9e55 = { cd 3a [2] e9 34 [2] c2 18 [2] ec 3a [2] f8 21 [2] f7 3b [2] e9 26 [2] eb 27 [2] f0 21 [2] ec 26 [2] f0 09 }

  condition:
    any of them
}