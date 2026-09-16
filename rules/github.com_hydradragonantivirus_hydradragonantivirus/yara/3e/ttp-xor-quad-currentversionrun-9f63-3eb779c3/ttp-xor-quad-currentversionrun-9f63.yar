rule TTP_XOR_QUAD_CurrentVersionRun_9f63 {
  strings:
    $key_9f63 = { cc 0c [2] e8 02 [2] c3 2e [2] ed 0c [2] f9 17 [2] f6 0d [2] e8 10 [2] ea 11 [2] f1 17 [2] ed 10 [2] f1 3f }

  condition:
    any of them
}