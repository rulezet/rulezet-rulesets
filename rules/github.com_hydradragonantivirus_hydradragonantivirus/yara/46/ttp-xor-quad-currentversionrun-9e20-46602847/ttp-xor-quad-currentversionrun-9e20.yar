rule TTP_XOR_QUAD_CurrentVersionRun_9e20 {
  strings:
    $key_9e20 = { cd 4f [2] e9 41 [2] c2 6d [2] ec 4f [2] f8 54 [2] f7 4e [2] e9 53 [2] eb 52 [2] f0 54 [2] ec 53 [2] f0 7c }

  condition:
    any of them
}