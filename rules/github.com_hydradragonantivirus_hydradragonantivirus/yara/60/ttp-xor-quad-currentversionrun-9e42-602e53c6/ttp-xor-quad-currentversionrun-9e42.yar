rule TTP_XOR_QUAD_CurrentVersionRun_9e42 {
  strings:
    $key_9e42 = { cd 2d [2] e9 23 [2] c2 0f [2] ec 2d [2] f8 36 [2] f7 2c [2] e9 31 [2] eb 30 [2] f0 36 [2] ec 31 [2] f0 1e }

  condition:
    any of them
}