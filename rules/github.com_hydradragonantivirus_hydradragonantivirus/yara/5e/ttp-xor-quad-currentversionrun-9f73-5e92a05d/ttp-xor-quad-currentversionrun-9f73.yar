rule TTP_XOR_QUAD_CurrentVersionRun_9f73 {
  strings:
    $key_9f73 = { cc 1c [2] e8 12 [2] c3 3e [2] ed 1c [2] f9 07 [2] f6 1d [2] e8 00 [2] ea 01 [2] f1 07 [2] ed 00 [2] f1 2f }

  condition:
    any of them
}