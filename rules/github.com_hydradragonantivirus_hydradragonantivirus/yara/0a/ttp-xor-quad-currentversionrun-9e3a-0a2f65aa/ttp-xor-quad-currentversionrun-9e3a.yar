rule TTP_XOR_QUAD_CurrentVersionRun_9e3a {
  strings:
    $key_9e3a = { cd 55 [2] e9 5b [2] c2 77 [2] ec 55 [2] f8 4e [2] f7 54 [2] e9 49 [2] eb 48 [2] f0 4e [2] ec 49 [2] f0 66 }

  condition:
    any of them
}