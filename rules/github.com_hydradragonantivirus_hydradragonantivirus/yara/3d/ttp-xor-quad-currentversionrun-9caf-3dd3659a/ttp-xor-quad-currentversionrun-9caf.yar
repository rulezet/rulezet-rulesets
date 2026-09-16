rule TTP_XOR_QUAD_CurrentVersionRun_9caf {
  strings:
    $key_9caf = { cf c0 [2] eb ce [2] c0 e2 [2] ee c0 [2] fa db [2] f5 c1 [2] eb dc [2] e9 dd [2] f2 db [2] ee dc [2] f2 f3 }

  condition:
    any of them
}