rule TTP_XOR_QUAD_CurrentVersionRun_9e5a {
  strings:
    $key_9e5a = { cd 35 [2] e9 3b [2] c2 17 [2] ec 35 [2] f8 2e [2] f7 34 [2] e9 29 [2] eb 28 [2] f0 2e [2] ec 29 [2] f0 06 }

  condition:
    any of them
}