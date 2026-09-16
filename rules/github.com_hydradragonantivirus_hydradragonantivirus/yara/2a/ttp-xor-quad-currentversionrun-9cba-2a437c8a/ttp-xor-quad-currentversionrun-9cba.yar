rule TTP_XOR_QUAD_CurrentVersionRun_9cba {
  strings:
    $key_9cba = { cf d5 [2] eb db [2] c0 f7 [2] ee d5 [2] fa ce [2] f5 d4 [2] eb c9 [2] e9 c8 [2] f2 ce [2] ee c9 [2] f2 e6 }

  condition:
    any of them
}