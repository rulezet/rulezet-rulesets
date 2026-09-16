rule TTP_XOR_QUAD_CurrentVersionRun_9e7a {
  strings:
    $key_9e7a = { cd 15 [2] e9 1b [2] c2 37 [2] ec 15 [2] f8 0e [2] f7 14 [2] e9 09 [2] eb 08 [2] f0 0e [2] ec 09 [2] f0 26 }

  condition:
    any of them
}