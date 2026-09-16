rule TTP_XOR_QUAD_CurrentVersionRun_9e1b {
  strings:
    $key_9e1b = { cd 74 [2] e9 7a [2] c2 56 [2] ec 74 [2] f8 6f [2] f7 75 [2] e9 68 [2] eb 69 [2] f0 6f [2] ec 68 [2] f0 47 }

  condition:
    any of them
}