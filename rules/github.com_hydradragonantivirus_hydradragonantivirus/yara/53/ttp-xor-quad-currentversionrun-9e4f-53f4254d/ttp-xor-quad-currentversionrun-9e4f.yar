rule TTP_XOR_QUAD_CurrentVersionRun_9e4f {
  strings:
    $key_9e4f = { cd 20 [2] e9 2e [2] c2 02 [2] ec 20 [2] f8 3b [2] f7 21 [2] e9 3c [2] eb 3d [2] f0 3b [2] ec 3c [2] f0 13 }

  condition:
    any of them
}