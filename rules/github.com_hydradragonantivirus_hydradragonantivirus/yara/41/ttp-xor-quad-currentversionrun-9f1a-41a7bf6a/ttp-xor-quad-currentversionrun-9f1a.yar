rule TTP_XOR_QUAD_CurrentVersionRun_9f1a {
  strings:
    $key_9f1a = { cc 75 [2] e8 7b [2] c3 57 [2] ed 75 [2] f9 6e [2] f6 74 [2] e8 69 [2] ea 68 [2] f1 6e [2] ed 69 [2] f1 46 }

  condition:
    any of them
}