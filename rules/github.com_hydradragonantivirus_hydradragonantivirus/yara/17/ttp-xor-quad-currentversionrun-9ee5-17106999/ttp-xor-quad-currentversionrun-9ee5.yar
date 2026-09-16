rule TTP_XOR_QUAD_CurrentVersionRun_9ee5 {
  strings:
    $key_9ee5 = { cd 8a [2] e9 84 [2] c2 a8 [2] ec 8a [2] f8 91 [2] f7 8b [2] e9 96 [2] eb 97 [2] f0 91 [2] ec 96 [2] f0 b9 }

  condition:
    any of them
}