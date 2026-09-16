rule TTP_XOR_QUAD_CurrentVersionRun_9c9c {
  strings:
    $key_9c9c = { cf f3 [2] eb fd [2] c0 d1 [2] ee f3 [2] fa e8 [2] f5 f2 [2] eb ef [2] e9 ee [2] f2 e8 [2] ee ef [2] f2 c0 }

  condition:
    any of them
}