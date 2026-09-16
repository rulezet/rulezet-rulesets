rule TTP_XOR_QUAD_CurrentVersionRun_9e6f {
  strings:
    $key_9e6f = { cd 00 [2] e9 0e [2] c2 22 [2] ec 00 [2] f8 1b [2] f7 01 [2] e9 1c [2] eb 1d [2] f0 1b [2] ec 1c [2] f0 33 }

  condition:
    any of them
}