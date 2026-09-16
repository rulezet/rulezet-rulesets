rule TTP_XOR_QUAD_CurrentVersionRun_9cb8 {
  strings:
    $key_9cb8 = { cf d7 [2] eb d9 [2] c0 f5 [2] ee d7 [2] fa cc [2] f5 d6 [2] eb cb [2] e9 ca [2] f2 cc [2] ee cb [2] f2 e4 }

  condition:
    any of them
}