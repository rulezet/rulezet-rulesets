rule TTP_XOR_QUAD_CurrentVersionRun_9f36 {
  strings:
    $key_9f36 = { cc 59 [2] e8 57 [2] c3 7b [2] ed 59 [2] f9 42 [2] f6 58 [2] e8 45 [2] ea 44 [2] f1 42 [2] ed 45 [2] f1 6a }

  condition:
    any of them
}