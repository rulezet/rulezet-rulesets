rule TTP_XOR_QUAD_CurrentVersionRun_9f31 {
  strings:
    $key_9f31 = { cc 5e [2] e8 50 [2] c3 7c [2] ed 5e [2] f9 45 [2] f6 5f [2] e8 42 [2] ea 43 [2] f1 45 [2] ed 42 [2] f1 6d }

  condition:
    any of them
}