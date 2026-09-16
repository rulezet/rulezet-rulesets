rule TTP_XOR_QUAD_CurrentVersionRun_9f26 {
  strings:
    $key_9f26 = { cc 49 [2] e8 47 [2] c3 6b [2] ed 49 [2] f9 52 [2] f6 48 [2] e8 55 [2] ea 54 [2] f1 52 [2] ed 55 [2] f1 7a }

  condition:
    any of them
}