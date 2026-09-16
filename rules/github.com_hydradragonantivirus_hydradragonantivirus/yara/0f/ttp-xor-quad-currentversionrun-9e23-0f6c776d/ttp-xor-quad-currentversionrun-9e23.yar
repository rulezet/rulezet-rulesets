rule TTP_XOR_QUAD_CurrentVersionRun_9e23 {
  strings:
    $key_9e23 = { cd 4c [2] e9 42 [2] c2 6e [2] ec 4c [2] f8 57 [2] f7 4d [2] e9 50 [2] eb 51 [2] f0 57 [2] ec 50 [2] f0 7f }

  condition:
    any of them
}