rule TTP_XOR_QUAD_CurrentVersionRun_9e10 {
  strings:
    $key_9e10 = { cd 7f [2] e9 71 [2] c2 5d [2] ec 7f [2] f8 64 [2] f7 7e [2] e9 63 [2] eb 62 [2] f0 64 [2] ec 63 [2] f0 4c }

  condition:
    any of them
}