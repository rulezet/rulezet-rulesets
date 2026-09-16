rule TTP_XOR_QUAD_CurrentVersionRun_9e1d {
  strings:
    $key_9e1d = { cd 72 [2] e9 7c [2] c2 50 [2] ec 72 [2] f8 69 [2] f7 73 [2] e9 6e [2] eb 6f [2] f0 69 [2] ec 6e [2] f0 41 }

  condition:
    any of them
}