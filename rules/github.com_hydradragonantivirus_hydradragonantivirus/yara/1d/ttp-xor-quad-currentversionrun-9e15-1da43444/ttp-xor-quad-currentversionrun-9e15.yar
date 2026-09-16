rule TTP_XOR_QUAD_CurrentVersionRun_9e15 {
  strings:
    $key_9e15 = { cd 7a [2] e9 74 [2] c2 58 [2] ec 7a [2] f8 61 [2] f7 7b [2] e9 66 [2] eb 67 [2] f0 61 [2] ec 66 [2] f0 49 }

  condition:
    any of them
}