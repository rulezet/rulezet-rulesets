rule TTP_XOR_QUAD_CurrentVersionRun_9e6b {
  strings:
    $key_9e6b = { cd 04 [2] e9 0a [2] c2 26 [2] ec 04 [2] f8 1f [2] f7 05 [2] e9 18 [2] eb 19 [2] f0 1f [2] ec 18 [2] f0 37 }

  condition:
    any of them
}