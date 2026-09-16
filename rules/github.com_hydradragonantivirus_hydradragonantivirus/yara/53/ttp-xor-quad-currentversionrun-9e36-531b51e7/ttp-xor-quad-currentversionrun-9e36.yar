rule TTP_XOR_QUAD_CurrentVersionRun_9e36 {
  strings:
    $key_9e36 = { cd 59 [2] e9 57 [2] c2 7b [2] ec 59 [2] f8 42 [2] f7 58 [2] e9 45 [2] eb 44 [2] f0 42 [2] ec 45 [2] f0 6a }

  condition:
    any of them
}