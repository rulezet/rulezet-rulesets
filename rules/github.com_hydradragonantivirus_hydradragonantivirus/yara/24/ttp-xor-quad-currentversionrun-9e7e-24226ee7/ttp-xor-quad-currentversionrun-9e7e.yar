rule TTP_XOR_QUAD_CurrentVersionRun_9e7e {
  strings:
    $key_9e7e = { cd 11 [2] e9 1f [2] c2 33 [2] ec 11 [2] f8 0a [2] f7 10 [2] e9 0d [2] eb 0c [2] f0 0a [2] ec 0d [2] f0 22 }

  condition:
    any of them
}