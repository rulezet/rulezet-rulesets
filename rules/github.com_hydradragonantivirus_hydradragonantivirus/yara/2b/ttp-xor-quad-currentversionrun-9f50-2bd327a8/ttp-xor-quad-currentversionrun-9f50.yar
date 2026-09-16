rule TTP_XOR_QUAD_CurrentVersionRun_9f50 {
  strings:
    $key_9f50 = { cc 3f [2] e8 31 [2] c3 1d [2] ed 3f [2] f9 24 [2] f6 3e [2] e8 23 [2] ea 22 [2] f1 24 [2] ed 23 [2] f1 0c }

  condition:
    any of them
}