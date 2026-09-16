rule TTP_XOR_QUAD_CurrentVersionRun_9e79 {
  strings:
    $key_9e79 = { cd 16 [2] e9 18 [2] c2 34 [2] ec 16 [2] f8 0d [2] f7 17 [2] e9 0a [2] eb 0b [2] f0 0d [2] ec 0a [2] f0 25 }

  condition:
    any of them
}