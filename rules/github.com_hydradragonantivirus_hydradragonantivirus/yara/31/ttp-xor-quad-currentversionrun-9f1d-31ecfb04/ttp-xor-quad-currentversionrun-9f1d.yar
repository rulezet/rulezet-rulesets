rule TTP_XOR_QUAD_CurrentVersionRun_9f1d {
  strings:
    $key_9f1d = { cc 72 [2] e8 7c [2] c3 50 [2] ed 72 [2] f9 69 [2] f6 73 [2] e8 6e [2] ea 6f [2] f1 69 [2] ed 6e [2] f1 41 }

  condition:
    any of them
}