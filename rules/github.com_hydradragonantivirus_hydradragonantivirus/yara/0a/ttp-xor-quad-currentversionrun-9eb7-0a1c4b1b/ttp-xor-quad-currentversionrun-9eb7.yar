rule TTP_XOR_QUAD_CurrentVersionRun_9eb7 {
  strings:
    $key_9eb7 = { cd d8 [2] e9 d6 [2] c2 fa [2] ec d8 [2] f8 c3 [2] f7 d9 [2] e9 c4 [2] eb c5 [2] f0 c3 [2] ec c4 [2] f0 eb }

  condition:
    any of them
}