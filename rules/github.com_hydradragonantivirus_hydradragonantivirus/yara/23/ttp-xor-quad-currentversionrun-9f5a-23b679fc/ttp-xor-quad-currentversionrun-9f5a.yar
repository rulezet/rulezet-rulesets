rule TTP_XOR_QUAD_CurrentVersionRun_9f5a {
  strings:
    $key_9f5a = { cc 35 [2] e8 3b [2] c3 17 [2] ed 35 [2] f9 2e [2] f6 34 [2] e8 29 [2] ea 28 [2] f1 2e [2] ed 29 [2] f1 06 }

  condition:
    any of them
}