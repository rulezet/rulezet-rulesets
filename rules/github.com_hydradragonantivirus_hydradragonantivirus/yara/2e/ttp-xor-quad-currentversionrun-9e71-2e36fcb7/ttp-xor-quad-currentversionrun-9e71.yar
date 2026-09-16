rule TTP_XOR_QUAD_CurrentVersionRun_9e71 {
  strings:
    $key_9e71 = { cd 1e [2] e9 10 [2] c2 3c [2] ec 1e [2] f8 05 [2] f7 1f [2] e9 02 [2] eb 03 [2] f0 05 [2] ec 02 [2] f0 2d }

  condition:
    any of them
}