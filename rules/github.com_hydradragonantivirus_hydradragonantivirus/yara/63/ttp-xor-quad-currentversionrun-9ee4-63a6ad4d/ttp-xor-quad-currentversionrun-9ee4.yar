rule TTP_XOR_QUAD_CurrentVersionRun_9ee4 {
  strings:
    $key_9ee4 = { cd 8b [2] e9 85 [2] c2 a9 [2] ec 8b [2] f8 90 [2] f7 8a [2] e9 97 [2] eb 96 [2] f0 90 [2] ec 97 [2] f0 b8 }

  condition:
    any of them
}