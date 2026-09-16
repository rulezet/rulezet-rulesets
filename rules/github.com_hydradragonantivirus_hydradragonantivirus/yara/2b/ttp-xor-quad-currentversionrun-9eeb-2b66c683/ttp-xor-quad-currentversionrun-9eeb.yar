rule TTP_XOR_QUAD_CurrentVersionRun_9eeb {
  strings:
    $key_9eeb = { cd 84 [2] e9 8a [2] c2 a6 [2] ec 84 [2] f8 9f [2] f7 85 [2] e9 98 [2] eb 99 [2] f0 9f [2] ec 98 [2] f0 b7 }

  condition:
    any of them
}