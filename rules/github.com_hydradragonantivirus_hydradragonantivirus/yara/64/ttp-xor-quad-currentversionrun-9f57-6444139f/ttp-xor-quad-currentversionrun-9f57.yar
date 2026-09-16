rule TTP_XOR_QUAD_CurrentVersionRun_9f57 {
  strings:
    $key_9f57 = { cc 38 [2] e8 36 [2] c3 1a [2] ed 38 [2] f9 23 [2] f6 39 [2] e8 24 [2] ea 25 [2] f1 23 [2] ed 24 [2] f1 0b }

  condition:
    any of them
}