rule TTP_XOR_QUAD_CurrentVersionRun_9e0c {
  strings:
    $key_9e0c = { cd 63 [2] e9 6d [2] c2 41 [2] ec 63 [2] f8 78 [2] f7 62 [2] e9 7f [2] eb 7e [2] f0 78 [2] ec 7f [2] f0 50 }

  condition:
    any of them
}