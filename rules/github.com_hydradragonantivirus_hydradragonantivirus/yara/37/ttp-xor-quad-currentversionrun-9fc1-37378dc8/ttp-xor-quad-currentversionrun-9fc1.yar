rule TTP_XOR_QUAD_CurrentVersionRun_9fc1 {
  strings:
    $key_9fc1 = { cc ae [2] e8 a0 [2] c3 8c [2] ed ae [2] f9 b5 [2] f6 af [2] e8 b2 [2] ea b3 [2] f1 b5 [2] ed b2 [2] f1 9d }

  condition:
    any of them
}