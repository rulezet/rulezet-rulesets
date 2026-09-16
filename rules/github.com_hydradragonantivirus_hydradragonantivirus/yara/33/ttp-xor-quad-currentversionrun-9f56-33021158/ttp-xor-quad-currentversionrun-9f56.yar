rule TTP_XOR_QUAD_CurrentVersionRun_9f56 {
  strings:
    $key_9f56 = { cc 39 [2] e8 37 [2] c3 1b [2] ed 39 [2] f9 22 [2] f6 38 [2] e8 25 [2] ea 24 [2] f1 22 [2] ed 25 [2] f1 0a }

  condition:
    any of them
}