rule TTP_XOR_QUAD_CurrentVersionRun_9cdd {
  strings:
    $key_9cdd = { cf b2 [2] eb bc [2] c0 90 [2] ee b2 [2] fa a9 [2] f5 b3 [2] eb ae [2] e9 af [2] f2 a9 [2] ee ae [2] f2 81 }

  condition:
    any of them
}