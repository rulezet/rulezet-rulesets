rule TTP_XOR_QUAD_CurrentVersionRun_9e4a {
  strings:
    $key_9e4a = { cd 25 [2] e9 2b [2] c2 07 [2] ec 25 [2] f8 3e [2] f7 24 [2] e9 39 [2] eb 38 [2] f0 3e [2] ec 39 [2] f0 16 }

  condition:
    any of them
}