rule TTP_XOR_QUAD_CurrentVersionRun_9e64 {
  strings:
    $key_9e64 = { cd 0b [2] e9 05 [2] c2 29 [2] ec 0b [2] f8 10 [2] f7 0a [2] e9 17 [2] eb 16 [2] f0 10 [2] ec 17 [2] f0 38 }

  condition:
    any of them
}