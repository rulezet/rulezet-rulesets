rule TTP_XOR_QUAD_CurrentVersionRun_9e2e {
  strings:
    $key_9e2e = { cd 41 [2] e9 4f [2] c2 63 [2] ec 41 [2] f8 5a [2] f7 40 [2] e9 5d [2] eb 5c [2] f0 5a [2] ec 5d [2] f0 72 }

  condition:
    any of them
}