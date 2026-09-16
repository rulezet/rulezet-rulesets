rule TTP_XOR_QUAD_CurrentVersionRun_9e6c {
  strings:
    $key_9e6c = { cd 03 [2] e9 0d [2] c2 21 [2] ec 03 [2] f8 18 [2] f7 02 [2] e9 1f [2] eb 1e [2] f0 18 [2] ec 1f [2] f0 30 }

  condition:
    any of them
}