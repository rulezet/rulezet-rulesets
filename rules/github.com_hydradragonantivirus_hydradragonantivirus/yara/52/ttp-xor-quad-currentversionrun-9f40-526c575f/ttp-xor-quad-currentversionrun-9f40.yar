rule TTP_XOR_QUAD_CurrentVersionRun_9f40 {
  strings:
    $key_9f40 = { cc 2f [2] e8 21 [2] c3 0d [2] ed 2f [2] f9 34 [2] f6 2e [2] e8 33 [2] ea 32 [2] f1 34 [2] ed 33 [2] f1 1c }

  condition:
    any of them
}