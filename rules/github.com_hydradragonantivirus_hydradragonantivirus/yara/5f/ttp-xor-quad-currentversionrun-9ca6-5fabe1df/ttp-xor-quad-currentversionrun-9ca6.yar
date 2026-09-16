rule TTP_XOR_QUAD_CurrentVersionRun_9ca6 {
  strings:
    $key_9ca6 = { cf c9 [2] eb c7 [2] c0 eb [2] ee c9 [2] fa d2 [2] f5 c8 [2] eb d5 [2] e9 d4 [2] f2 d2 [2] ee d5 [2] f2 fa }

  condition:
    any of them
}