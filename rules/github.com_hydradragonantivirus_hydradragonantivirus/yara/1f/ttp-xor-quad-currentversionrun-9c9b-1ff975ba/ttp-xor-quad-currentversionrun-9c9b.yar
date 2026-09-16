rule TTP_XOR_QUAD_CurrentVersionRun_9c9b {
  strings:
    $key_9c9b = { cf f4 [2] eb fa [2] c0 d6 [2] ee f4 [2] fa ef [2] f5 f5 [2] eb e8 [2] e9 e9 [2] f2 ef [2] ee e8 [2] f2 c7 }

  condition:
    any of them
}