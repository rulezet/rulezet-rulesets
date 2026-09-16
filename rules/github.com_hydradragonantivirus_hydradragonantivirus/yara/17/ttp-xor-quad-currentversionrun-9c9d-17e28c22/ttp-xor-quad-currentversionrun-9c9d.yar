rule TTP_XOR_QUAD_CurrentVersionRun_9c9d {
  strings:
    $key_9c9d = { cf f2 [2] eb fc [2] c0 d0 [2] ee f2 [2] fa e9 [2] f5 f3 [2] eb ee [2] e9 ef [2] f2 e9 [2] ee ee [2] f2 c1 }

  condition:
    any of them
}