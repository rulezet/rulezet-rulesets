rule TTP_XOR_QUAD_CurrentVersionRun_9e6d {
  strings:
    $key_9e6d = { cd 02 [2] e9 0c [2] c2 20 [2] ec 02 [2] f8 19 [2] f7 03 [2] e9 1e [2] eb 1f [2] f0 19 [2] ec 1e [2] f0 31 }

  condition:
    any of them
}