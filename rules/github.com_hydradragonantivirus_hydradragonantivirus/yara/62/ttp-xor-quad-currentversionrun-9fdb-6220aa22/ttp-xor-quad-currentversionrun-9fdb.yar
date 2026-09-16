rule TTP_XOR_QUAD_CurrentVersionRun_9fdb {
  strings:
    $key_9fdb = { cc b4 [2] e8 ba [2] c3 96 [2] ed b4 [2] f9 af [2] f6 b5 [2] e8 a8 [2] ea a9 [2] f1 af [2] ed a8 [2] f1 87 }

  condition:
    any of them
}