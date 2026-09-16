rule TTP_XOR_QUAD_CurrentVersionRun_9fce {
  strings:
    $key_9fce = { cc a1 [2] e8 af [2] c3 83 [2] ed a1 [2] f9 ba [2] f6 a0 [2] e8 bd [2] ea bc [2] f1 ba [2] ed bd [2] f1 92 }

  condition:
    any of them
}