rule TTP_XOR_QUAD_CurrentVersionRun_9e1c {
  strings:
    $key_9e1c = { cd 73 [2] e9 7d [2] c2 51 [2] ec 73 [2] f8 68 [2] f7 72 [2] e9 6f [2] eb 6e [2] f0 68 [2] ec 6f [2] f0 40 }

  condition:
    any of them
}