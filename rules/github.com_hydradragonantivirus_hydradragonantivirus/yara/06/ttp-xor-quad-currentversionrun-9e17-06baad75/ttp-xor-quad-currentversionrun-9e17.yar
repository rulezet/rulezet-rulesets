rule TTP_XOR_QUAD_CurrentVersionRun_9e17 {
  strings:
    $key_9e17 = { cd 78 [2] e9 76 [2] c2 5a [2] ec 78 [2] f8 63 [2] f7 79 [2] e9 64 [2] eb 65 [2] f0 63 [2] ec 64 [2] f0 4b }

  condition:
    any of them
}