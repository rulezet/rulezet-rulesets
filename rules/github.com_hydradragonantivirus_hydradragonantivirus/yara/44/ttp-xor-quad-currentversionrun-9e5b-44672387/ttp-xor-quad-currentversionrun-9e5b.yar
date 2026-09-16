rule TTP_XOR_QUAD_CurrentVersionRun_9e5b {
  strings:
    $key_9e5b = { cd 34 [2] e9 3a [2] c2 16 [2] ec 34 [2] f8 2f [2] f7 35 [2] e9 28 [2] eb 29 [2] f0 2f [2] ec 28 [2] f0 07 }

  condition:
    any of them
}