rule TTP_XOR_QUAD_CurrentVersionRun_9e52 {
  strings:
    $key_9e52 = { cd 3d [2] e9 33 [2] c2 1f [2] ec 3d [2] f8 26 [2] f7 3c [2] e9 21 [2] eb 20 [2] f0 26 [2] ec 21 [2] f0 0e }

  condition:
    any of them
}