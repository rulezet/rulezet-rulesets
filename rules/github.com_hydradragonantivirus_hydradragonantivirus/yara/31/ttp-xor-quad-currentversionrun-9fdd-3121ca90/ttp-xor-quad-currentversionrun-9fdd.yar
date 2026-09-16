rule TTP_XOR_QUAD_CurrentVersionRun_9fdd {
  strings:
    $key_9fdd = { cc b2 [2] e8 bc [2] c3 90 [2] ed b2 [2] f9 a9 [2] f6 b3 [2] e8 ae [2] ea af [2] f1 a9 [2] ed ae [2] f1 81 }

  condition:
    any of them
}