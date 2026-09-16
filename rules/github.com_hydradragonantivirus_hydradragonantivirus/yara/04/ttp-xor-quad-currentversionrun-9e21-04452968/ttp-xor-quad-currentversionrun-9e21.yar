rule TTP_XOR_QUAD_CurrentVersionRun_9e21 {
  strings:
    $key_9e21 = { cd 4e [2] e9 40 [2] c2 6c [2] ec 4e [2] f8 55 [2] f7 4f [2] e9 52 [2] eb 53 [2] f0 55 [2] ec 52 [2] f0 7d }

  condition:
    any of them
}