rule TTP_XOR_QUAD_CurrentVersionRun_9f66 {
  strings:
    $key_9f66 = { cc 09 [2] e8 07 [2] c3 2b [2] ed 09 [2] f9 12 [2] f6 08 [2] e8 15 [2] ea 14 [2] f1 12 [2] ed 15 [2] f1 3a }

  condition:
    any of them
}