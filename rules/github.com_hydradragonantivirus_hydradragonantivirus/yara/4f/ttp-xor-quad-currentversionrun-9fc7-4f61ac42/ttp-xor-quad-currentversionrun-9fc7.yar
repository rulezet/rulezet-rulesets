rule TTP_XOR_QUAD_CurrentVersionRun_9fc7 {
  strings:
    $key_9fc7 = { cc a8 [2] e8 a6 [2] c3 8a [2] ed a8 [2] f9 b3 [2] f6 a9 [2] e8 b4 [2] ea b5 [2] f1 b3 [2] ed b4 [2] f1 9b }

  condition:
    any of them
}