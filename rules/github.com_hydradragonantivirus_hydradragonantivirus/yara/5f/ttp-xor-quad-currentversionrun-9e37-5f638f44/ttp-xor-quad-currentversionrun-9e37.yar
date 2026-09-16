rule TTP_XOR_QUAD_CurrentVersionRun_9e37 {
  strings:
    $key_9e37 = { cd 58 [2] e9 56 [2] c2 7a [2] ec 58 [2] f8 43 [2] f7 59 [2] e9 44 [2] eb 45 [2] f0 43 [2] ec 44 [2] f0 6b }

  condition:
    any of them
}