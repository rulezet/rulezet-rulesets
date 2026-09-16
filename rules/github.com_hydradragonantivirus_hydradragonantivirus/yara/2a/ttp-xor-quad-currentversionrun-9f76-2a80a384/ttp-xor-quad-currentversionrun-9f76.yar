rule TTP_XOR_QUAD_CurrentVersionRun_9f76 {
  strings:
    $key_9f76 = { cc 19 [2] e8 17 [2] c3 3b [2] ed 19 [2] f9 02 [2] f6 18 [2] e8 05 [2] ea 04 [2] f1 02 [2] ed 05 [2] f1 2a }

  condition:
    any of them
}