rule TTP_XOR_QUAD_CurrentVersionRun_9ca8 {
  strings:
    $key_9ca8 = { cf c7 [2] eb c9 [2] c0 e5 [2] ee c7 [2] fa dc [2] f5 c6 [2] eb db [2] e9 da [2] f2 dc [2] ee db [2] f2 f4 }

  condition:
    any of them
}