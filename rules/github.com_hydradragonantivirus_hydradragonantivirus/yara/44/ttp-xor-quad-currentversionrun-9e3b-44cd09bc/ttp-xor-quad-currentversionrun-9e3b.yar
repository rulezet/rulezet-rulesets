rule TTP_XOR_QUAD_CurrentVersionRun_9e3b {
  strings:
    $key_9e3b = { cd 54 [2] e9 5a [2] c2 76 [2] ec 54 [2] f8 4f [2] f7 55 [2] e9 48 [2] eb 49 [2] f0 4f [2] ec 48 [2] f0 67 }

  condition:
    any of them
}