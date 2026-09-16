rule TTP_XOR_QUAD_CurrentVersionRun_9eea {
  strings:
    $key_9eea = { cd 85 [2] e9 8b [2] c2 a7 [2] ec 85 [2] f8 9e [2] f7 84 [2] e9 99 [2] eb 98 [2] f0 9e [2] ec 99 [2] f0 b6 }

  condition:
    any of them
}