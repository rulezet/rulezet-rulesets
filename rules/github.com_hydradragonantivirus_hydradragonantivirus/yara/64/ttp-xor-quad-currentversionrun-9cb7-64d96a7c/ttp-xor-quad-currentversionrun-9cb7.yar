rule TTP_XOR_QUAD_CurrentVersionRun_9cb7 {
  strings:
    $key_9cb7 = { cf d8 [2] eb d6 [2] c0 fa [2] ee d8 [2] fa c3 [2] f5 d9 [2] eb c4 [2] e9 c5 [2] f2 c3 [2] ee c4 [2] f2 eb }

  condition:
    any of them
}