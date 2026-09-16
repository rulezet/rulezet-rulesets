rule TTP_XOR_QUAD_CurrentVersionRun_9e51 {
  strings:
    $key_9e51 = { cd 3e [2] e9 30 [2] c2 1c [2] ec 3e [2] f8 25 [2] f7 3f [2] e9 22 [2] eb 23 [2] f0 25 [2] ec 22 [2] f0 0d }

  condition:
    any of them
}