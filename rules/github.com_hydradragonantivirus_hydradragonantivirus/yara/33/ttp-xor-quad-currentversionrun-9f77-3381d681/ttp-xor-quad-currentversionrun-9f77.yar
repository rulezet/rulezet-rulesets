rule TTP_XOR_QUAD_CurrentVersionRun_9f77 {
  strings:
    $key_9f77 = { cc 18 [2] e8 16 [2] c3 3a [2] ed 18 [2] f9 03 [2] f6 19 [2] e8 04 [2] ea 05 [2] f1 03 [2] ed 04 [2] f1 2b }

  condition:
    any of them
}